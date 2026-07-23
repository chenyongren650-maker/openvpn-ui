package services

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	mi "github.com/d3vilh/openvpn-server-config/server/mi"
)

const (
	auditActionArchive  = "certificate.archive"
	auditActionDownload = "certificate.download"
	auditActionRevoke   = "certificate.revoke"
	auditTargetType     = "certificate"
)

var (
	ErrCertificateNotFound        = errors.New("certificate not found")
	ErrCertificateForbidden       = errors.New("certificate lifecycle action requires administrator permission")
	ErrCertificateInvalidState    = errors.New("certificate lifecycle state does not allow this action")
	ErrCertificateConfirmation    = errors.New("certificate name confirmation does not match")
	ErrCertificateIdentity        = errors.New("certificate identity is invalid")
	ErrCertificatePKIMismatch     = errors.New("certificate database and PKI identities do not match")
	ErrCertificateCommand         = errors.New("certificate revocation command failed")
	ErrCertificateCRL             = errors.New("certificate revocation list generation failed")
	ErrCertificateDownloadBlocked = errors.New("certificate configuration download is blocked")
)

var (
	certificateCommonNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)
	certificateSerialPatternSafe = regexp.MustCompile(`^[0-9A-Fa-f]{1,128}$`)
	auditRequestIDPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// CertificateLifecycleActor contains only the non-sensitive request metadata
// required for authorization and audit.
type CertificateLifecycleActor struct {
	UserID    int64
	IsAdmin   bool
	SourceIP  string
	RequestID string
}

// CertificateLifecycleConfig identifies the isolated Easy-RSA PKI and
// management interface used by lifecycle operations.
type CertificateLifecycleConfig struct {
	EasyRSABinary        string
	EasyRSAWorkingDir    string
	PKIDir               string
	ManagementNetwork    string
	ManagementAddress    string
	ProtectedCommonNames []string
}

// CertificateState is the database-owned lifecycle state used by controllers.
type CertificateState struct {
	ID                 int64
	CommonName         string
	SerialNumber       string
	Status             string
	StaticIP           string
	TechnicalExpiresAt *time.Time
	RevokedAt          *time.Time
	ArchivedAt         *time.Time
	Protected          bool
}

type ArchiveCertificateResult struct {
	AlreadyArchived bool
}

type RevokeCertificateResult struct {
	AlreadyRevoked   bool
	Disconnected     bool
	DisconnectFailed bool
}

type lifecycleCommandRunner interface {
	Run(context.Context, string, []string, string, []string) error
}

type lifecycleDisconnector interface {
	Disconnect(context.Context, string) (bool, error)
}

type osLifecycleCommandRunner struct{}

func (osLifecycleCommandRunner) Run(
	ctx context.Context,
	binary string,
	args []string,
	workingDir string,
	extraEnvironment []string,
) error {
	command := exec.CommandContext(ctx, binary, args...)
	command.Dir = workingDir
	command.Env = append(os.Environ(), extraEnvironment...)
	// Do not capture or log Easy-RSA output. It can contain certificate
	// metadata that does not belong in application logs.
	if err := command.Run(); err != nil {
		return ErrCertificateCommand
	}
	return nil
}

type managementLifecycleDisconnector struct {
	network string
	address string
}

func (d managementLifecycleDisconnector) Disconnect(
	ctx context.Context,
	commonName string,
) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	client := mi.NewClient(d.network, d.address)
	status, err := client.GetStatus()
	if err != nil {
		return false, err
	}
	for _, connectedClient := range status.ClientList {
		if connectedClient != nil && connectedClient.CommonName == commonName {
			if _, err := client.KillSession(commonName); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

// CertificateLifecycleService owns certificate lifecycle state transitions.
// One service instance is used by one UI process; its mutex serializes PKI
// commands with their database compensation state.
type CertificateLifecycleService struct {
	db                   *sql.DB
	easyRSABinary        string
	easyRSAWorkingDir    string
	pkiDir               string
	indexPath            string
	crlPath              string
	protectedCommonNames map[string]struct{}
	runner               lifecycleCommandRunner
	disconnector         lifecycleDisconnector
	mu                   sync.Mutex
	now                  func() time.Time
}

func NewCertificateLifecycleService(
	db *sql.DB,
	config CertificateLifecycleConfig,
) (*CertificateLifecycleService, error) {
	if db == nil {
		return nil, errors.New("certificate lifecycle database is nil")
	}

	easyRSAWorkingDir, err := cleanAbsolutePath(config.EasyRSAWorkingDir)
	if err != nil {
		return nil, fmt.Errorf("resolve Easy-RSA working directory: %w", err)
	}
	easyRSABinary, err := cleanAbsolutePath(config.EasyRSABinary)
	if err != nil {
		return nil, fmt.Errorf("resolve Easy-RSA binary: %w", err)
	}
	pkiDir, err := cleanAbsolutePath(config.PKIDir)
	if err != nil {
		return nil, fmt.Errorf("resolve Easy-RSA PKI directory: %w", err)
	}
	if !pathIsWithin(easyRSAWorkingDir, easyRSABinary) {
		return nil, errors.New("Easy-RSA binary must be inside its configured working directory")
	}
	protected := map[string]struct{}{"server": {}}
	for _, commonName := range config.ProtectedCommonNames {
		commonName = strings.TrimSpace(commonName)
		if commonName != "" {
			protected[strings.ToLower(commonName)] = struct{}{}
		}
	}

	return &CertificateLifecycleService{
		db:                   db,
		easyRSABinary:        easyRSABinary,
		easyRSAWorkingDir:    easyRSAWorkingDir,
		pkiDir:               pkiDir,
		indexPath:            filepath.Join(pkiDir, "index.txt"),
		crlPath:              filepath.Join(pkiDir, "crl.pem"),
		protectedCommonNames: protected,
		runner:               osLifecycleCommandRunner{},
		disconnector: managementLifecycleDisconnector{
			network: config.ManagementNetwork,
			address: config.ManagementAddress,
		},
		now: func() time.Time { return time.Now().UTC() },
	}, nil
}

func cleanAbsolutePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(absolute), nil
}

func pathIsWithin(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return relative != ".." &&
		relative != "." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// ValidateCertificateCommonName permits only the portable certificate names
// that can safely be used as Easy-RSA arguments and file basenames.
func ValidateCertificateCommonName(commonName string) bool {
	if commonName == "." || commonName == ".." {
		return false
	}
	return certificateCommonNamePattern.MatchString(commonName)
}

func ValidateCertificateSerial(serial string) bool {
	return certificateSerialPatternSafe.MatchString(serial)
}

func (s *CertificateLifecycleService) IsProtectedCommonName(commonName string) bool {
	_, protected := s.protectedCommonNames[strings.ToLower(commonName)]
	return protected
}

func (s *CertificateLifecycleService) SyncCertificateMetadata(
	ctx context.Context,
) (CertificateImportResult, error) {
	return ImportCertificateMetadataFile(ctx, s.db, s.indexPath)
}

func (s *CertificateLifecycleService) ListCertificateStates(
	ctx context.Context,
	includeArchived bool,
) ([]CertificateState, error) {
	operator := "IS NULL"
	if includeArchived {
		operator = "IS NOT NULL"
	}
	rows, err := s.db.QueryContext(ctx, `SELECT
		id, common_name, serial_number, status, static_ip,
		technical_expires_at, revoked_at, archived_at
	FROM certificates
	WHERE archived_at `+operator+`
	ORDER BY common_name, id`)
	if err != nil {
		return nil, fmt.Errorf("list certificate lifecycle state: %w", err)
	}
	defer rows.Close()

	states := make([]CertificateState, 0)
	for rows.Next() {
		state, err := scanCertificateState(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan certificate lifecycle state: %w", err)
		}
		state.Protected = s.IsProtectedCommonName(state.CommonName)
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate certificate lifecycle state: %w", err)
	}
	return states, nil
}

func (s *CertificateLifecycleService) DownloadableCertificate(
	ctx context.Context,
	certificateID int64,
) (CertificateState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if certificateID <= 0 {
		return CertificateState{}, ErrCertificateNotFound
	}
	state, err := s.loadCertificate(ctx, certificateID)
	if err != nil {
		return CertificateState{}, err
	}
	if state.Protected || state.Status != "valid" || state.ArchivedAt != nil {
		return CertificateState{}, ErrCertificateDownloadBlocked
	}
	if !ValidateCertificateCommonName(state.CommonName) ||
		!ValidateCertificateSerial(state.SerialNumber) {
		return CertificateState{}, ErrCertificateIdentity
	}
	pkiRecord, err := s.loadPKICertificate(state.SerialNumber)
	if err != nil || pkiRecord.CommonName != state.CommonName ||
		pkiRecord.Status != "valid" {
		return CertificateState{}, ErrCertificateDownloadBlocked
	}
	return state, nil
}

// RecordCertificateDownloadAudit records a download outcome without storing
// configuration contents, key material, or certificate metadata.
func (s *CertificateLifecycleService) RecordCertificateDownloadAudit(
	ctx context.Context,
	certificateID int64,
	actor CertificateLifecycleActor,
	result string,
	errorSummary string,
) error {
	if result != "success" && result != "failed" {
		return errors.New("invalid certificate download audit result")
	}
	return s.recordAudit(
		ctx,
		s.db,
		actor,
		auditActionDownload,
		certificateID,
		"certificate configuration download",
		result,
		errorSummary,
	)
}

func (s *CertificateLifecycleService) ArchiveCertificate(
	ctx context.Context,
	certificateID int64,
	actor CertificateLifecycleActor,
) (ArchiveCertificateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if certificateID <= 0 {
		return ArchiveCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionArchive, certificateID, "invalid_target", ErrCertificateNotFound,
		)
	}
	if !actor.IsAdmin {
		return ArchiveCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionArchive, certificateID, "permission_denied", ErrCertificateForbidden,
		)
	}

	state, err := s.loadCertificate(ctx, certificateID)
	if err != nil {
		return ArchiveCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionArchive, certificateID, "not_found", err,
		)
	}
	if state.ArchivedAt != nil || state.Status == "archived" {
		if err := s.recordAudit(
			ctx, s.db, actor, auditActionArchive, certificateID,
			"certificate archive", "already_archived", "",
		); err != nil {
			return ArchiveCertificateResult{}, err
		}
		return ArchiveCertificateResult{AlreadyArchived: true}, nil
	}
	if state.Status != "revoked" {
		return ArchiveCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionArchive, certificateID, "invalid_state", ErrCertificateInvalidState,
		)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ArchiveCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionArchive, certificateID, "database_failure", err,
		)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, `UPDATE certificates
		SET status = 'archived', archived_at = ?
		WHERE id = ? AND status = 'revoked' AND archived_at IS NULL`,
		s.now().UTC(), certificateID,
	)
	if err != nil {
		_ = tx.Rollback()
		return ArchiveCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionArchive, certificateID, "database_failure", err,
		)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected != 1 {
		_ = tx.Rollback()
		return ArchiveCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionArchive, certificateID, "concurrent_state_change",
			ErrCertificateInvalidState,
		)
	}
	if err := s.recordAudit(
		ctx, tx, actor, auditActionArchive, certificateID,
		"certificate archive", "success", "",
	); err != nil {
		return ArchiveCertificateResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return ArchiveCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionArchive, certificateID, "database_failure", err,
		)
	}
	return ArchiveCertificateResult{}, nil
}

func (s *CertificateLifecycleService) RevokeCertificate(
	ctx context.Context,
	certificateID int64,
	confirmation string,
	actor CertificateLifecycleActor,
) (RevokeCertificateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if certificateID <= 0 {
		return RevokeCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionRevoke, certificateID, "invalid_target", ErrCertificateNotFound,
		)
	}
	if !actor.IsAdmin {
		return RevokeCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionRevoke, certificateID, "permission_denied", ErrCertificateForbidden,
		)
	}

	state, err := s.loadCertificate(ctx, certificateID)
	if err != nil {
		return RevokeCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionRevoke, certificateID, "not_found", err,
		)
	}
	if state.Status == "revoked" || state.Status == "archived" || state.ArchivedAt != nil {
		if err := s.recordAudit(
			ctx, s.db, actor, auditActionRevoke, certificateID,
			"certificate revocation", "already_revoked", "",
		); err != nil {
			return RevokeCertificateResult{}, err
		}
		return RevokeCertificateResult{AlreadyRevoked: true}, nil
	}
	if state.Status != "valid" && state.Status != "expired" {
		return RevokeCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionRevoke, certificateID, "invalid_state", ErrCertificateInvalidState,
		)
	}
	if !constantTimeStringEqual(confirmation, state.CommonName) {
		return RevokeCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionRevoke, certificateID, "confirmation_mismatch",
			ErrCertificateConfirmation,
		)
	}
	if !ValidateCertificateCommonName(state.CommonName) ||
		!ValidateCertificateSerial(state.SerialNumber) ||
		s.IsProtectedCommonName(state.CommonName) {
		return RevokeCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionRevoke, certificateID, "invalid_identity",
			ErrCertificateIdentity,
		)
	}

	pkiRecord, err := s.loadPKICertificate(state.SerialNumber)
	if err != nil {
		return RevokeCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionRevoke, certificateID, "pki_read_failed", err,
		)
	}
	if pkiRecord.CommonName != state.CommonName {
		return RevokeCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionRevoke, certificateID, "pki_identity_mismatch",
			ErrCertificatePKIMismatch,
		)
	}

	if pkiRecord.Status != "revoked" {
		if pkiRecord.Status != "valid" && pkiRecord.Status != "expired" {
			return RevokeCertificateResult{}, s.auditFailure(
				ctx, actor, auditActionRevoke, certificateID, "pki_invalid_state",
				ErrCertificateInvalidState,
			)
		}
		if err := s.runEasyRSA(
			ctx,
			[]string{"--batch", "--pki-dir=" + s.pkiDir, "revoke", state.CommonName},
		); err != nil {
			return RevokeCertificateResult{}, s.auditFailure(
				ctx, actor, auditActionRevoke, certificateID, "revoke_command_failed",
				ErrCertificateCommand,
			)
		}
		pkiRecord, err = s.loadPKICertificate(state.SerialNumber)
		if err != nil || pkiRecord.CommonName != state.CommonName ||
			pkiRecord.Status != "revoked" || pkiRecord.RevokedAt == nil {
			return RevokeCertificateResult{}, s.auditFailure(
				ctx, actor, auditActionRevoke, certificateID, "revoke_verification_failed",
				ErrCertificatePKIMismatch,
			)
		}
	}

	if err := s.runEasyRSA(
		ctx,
		[]string{"--batch", "--pki-dir=" + s.pkiDir, "gen-crl"},
	); err != nil {
		return RevokeCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionRevoke, certificateID, "crl_command_failed",
			ErrCertificateCRL,
		)
	}
	if crlInfo, err := os.Stat(s.crlPath); err != nil || !crlInfo.Mode().IsRegular() {
		return RevokeCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionRevoke, certificateID, "crl_verification_failed",
			ErrCertificateCRL,
		)
	}

	disconnected, disconnectErr := s.disconnector.Disconnect(ctx, state.CommonName)
	auditResult := "success"
	auditError := ""
	if disconnectErr != nil {
		auditResult = "success_with_warning"
		auditError = "disconnect_failed"
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RevokeCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionRevoke, certificateID, "database_failure", err,
		)
	}
	defer tx.Rollback()

	revokedAt := s.now().UTC()
	if pkiRecord.RevokedAt != nil {
		revokedAt = pkiRecord.RevokedAt.UTC()
	}
	updateResult, err := tx.ExecContext(ctx, `UPDATE certificates
		SET status = 'revoked', revoked_at = ?
		WHERE id = ? AND status IN ('valid', 'expired') AND archived_at IS NULL`,
		revokedAt, certificateID,
	)
	if err != nil {
		_ = tx.Rollback()
		return RevokeCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionRevoke, certificateID, "database_failure", err,
		)
	}
	rowsAffected, err := updateResult.RowsAffected()
	if err != nil || rowsAffected != 1 {
		_ = tx.Rollback()
		return RevokeCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionRevoke, certificateID, "concurrent_state_change",
			ErrCertificateInvalidState,
		)
	}

	if state.StaticIP != "" {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ip_allocations (
			ip_address, pool_name, certificate_id, status,
			allocated_at, pending_release_at, released_at, notes
		) VALUES (?, 'restricted', ?, 'pending_release', ?, ?, NULL, '')
		ON CONFLICT(certificate_id) DO UPDATE SET
			ip_address = excluded.ip_address,
			pool_name = excluded.pool_name,
			status = 'pending_release',
			pending_release_at = excluded.pending_release_at,
			released_at = NULL`,
			state.StaticIP, certificateID, revokedAt, revokedAt,
		); err != nil {
			_ = tx.Rollback()
			return RevokeCertificateResult{}, s.auditFailure(
				ctx, actor, auditActionRevoke, certificateID, "ip_allocation_update_failed", err,
			)
		}
	}

	if err := s.recordAudit(
		ctx, tx, actor, auditActionRevoke, certificateID,
		"certificate revocation", auditResult, auditError,
	); err != nil {
		return RevokeCertificateResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return RevokeCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionRevoke, certificateID, "database_failure", err,
		)
	}

	return RevokeCertificateResult{
		Disconnected:     disconnected,
		DisconnectFailed: disconnectErr != nil,
	}, nil
}

func (s *CertificateLifecycleService) runEasyRSA(
	ctx context.Context,
	args []string,
) error {
	return s.runner.Run(
		ctx,
		s.easyRSABinary,
		append([]string(nil), args...),
		s.easyRSAWorkingDir,
		[]string{"EASYRSA_BATCH=1"},
	)
}

func (s *CertificateLifecycleService) loadPKICertificate(
	serialNumber string,
) (certificateMetadata, error) {
	indexFile, err := os.Open(s.indexPath)
	if err != nil {
		return certificateMetadata{}, fmt.Errorf("open PKI certificate index: %w", err)
	}
	defer indexFile.Close()

	records, err := parseCertificateIndex(indexFile, s.now().UTC())
	if err != nil {
		return certificateMetadata{}, err
	}
	normalizedSerial := strings.ToUpper(serialNumber)
	for _, record := range records {
		if record.SerialNumber == normalizedSerial {
			return record, nil
		}
	}
	return certificateMetadata{}, ErrCertificatePKIMismatch
}

func (s *CertificateLifecycleService) loadCertificate(
	ctx context.Context,
	certificateID int64,
) (CertificateState, error) {
	row := s.db.QueryRowContext(ctx, `SELECT
		id, common_name, serial_number, status, static_ip,
		technical_expires_at, revoked_at, archived_at
	FROM certificates WHERE id = ?`, certificateID)
	state, err := scanCertificateState(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return CertificateState{}, ErrCertificateNotFound
	}
	if err != nil {
		return CertificateState{}, fmt.Errorf("read certificate lifecycle state: %w", err)
	}
	state.Protected = s.IsProtectedCommonName(state.CommonName)
	return state, nil
}

type rowScanner func(...any) error

func scanCertificateState(scan rowScanner) (CertificateState, error) {
	var state CertificateState
	var staticIP sql.NullString
	var technicalExpiresAt, revokedAt, archivedAt sql.NullTime
	if err := scan(
		&state.ID,
		&state.CommonName,
		&state.SerialNumber,
		&state.Status,
		&staticIP,
		&technicalExpiresAt,
		&revokedAt,
		&archivedAt,
	); err != nil {
		return CertificateState{}, err
	}
	if staticIP.Valid {
		state.StaticIP = staticIP.String
	}
	if technicalExpiresAt.Valid {
		value := technicalExpiresAt.Time.UTC()
		state.TechnicalExpiresAt = &value
	}
	if revokedAt.Valid {
		value := revokedAt.Time.UTC()
		state.RevokedAt = &value
	}
	if archivedAt.Valid {
		value := archivedAt.Time.UTC()
		state.ArchivedAt = &value
	}
	return state, nil
}

type auditExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func (s *CertificateLifecycleService) recordAudit(
	ctx context.Context,
	executor auditExecutor,
	actor CertificateLifecycleActor,
	action string,
	certificateID int64,
	summary string,
	result string,
	errorSummary string,
) error {
	requestID := actor.RequestID
	if !auditRequestIDPattern.MatchString(requestID) {
		requestID = "unavailable"
	}
	sourceIP := normalizeAuditSourceIP(actor.SourceIP)
	_, err := executor.ExecContext(ctx, `INSERT INTO audit_logs (
		actor_user_id, source_ip, action, target_type, target_id,
		summary, result, error_summary, request_id, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nullableActorUserID(actor.UserID),
		sourceIP,
		action,
		auditTargetType,
		strconv.FormatInt(certificateID, 10),
		summary,
		result,
		errorSummary,
		requestID,
		s.now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("write certificate lifecycle audit: %w", err)
	}
	return nil
}

func (s *CertificateLifecycleService) auditFailure(
	ctx context.Context,
	actor CertificateLifecycleActor,
	action string,
	certificateID int64,
	errorSummary string,
	operationError error,
) error {
	_ = s.recordAudit(
		ctx,
		s.db,
		actor,
		action,
		certificateID,
		"certificate lifecycle operation",
		"failed",
		errorSummary,
	)
	return operationError
}

func normalizeAuditSourceIP(source string) string {
	source = strings.TrimSpace(source)
	if host, _, err := net.SplitHostPort(source); err == nil {
		source = host
	}
	parsed := net.ParseIP(source)
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

func nullableActorUserID(userID int64) any {
	if userID <= 0 {
		return nil
	}
	return userID
}

func constantTimeStringEqual(left, right string) bool {
	leftBytes := []byte(left)
	rightBytes := []byte(right)
	if len(leftBytes) != len(rightBytes) {
		return false
	}
	return subtle.ConstantTimeCompare(leftBytes, rightBytes) == 1
}
