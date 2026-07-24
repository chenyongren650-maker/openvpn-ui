package services

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
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
	CertificateAuditActionArchive  = "certificate.archive"
	CertificateAuditActionCreate   = "certificate.create"
	CertificateAuditActionDownload = "certificate.download"
	CertificateAuditActionReload   = "certificate.reload"
	CertificateAuditActionRenew    = "certificate.renew"
	CertificateAuditActionRestart  = "certificate.restart"
	CertificateAuditActionRevoke   = "certificate.revoke"
	CertificateAuditActionTOTPQR   = "certificate.totp_qr_view"
	CertificateAuditResultStarted  = "started"

	auditActionArchive       = CertificateAuditActionArchive
	auditActionDownload      = CertificateAuditActionDownload
	auditActionRevoke        = CertificateAuditActionRevoke
	auditActionTOTPQR        = CertificateAuditActionTOTPQR
	auditTargetType          = "certificate"
	defaultManagementTimeout = 5 * time.Second
)

var (
	ErrCertificateNotFound           = errors.New("certificate not found")
	ErrCertificateForbidden          = errors.New("certificate lifecycle action requires administrator permission")
	ErrCertificateInvalidState       = errors.New("certificate lifecycle state does not allow this action")
	ErrCertificateConfirmation       = errors.New("certificate name confirmation does not match")
	ErrCertificateIdentity           = errors.New("certificate identity is invalid")
	ErrCertificatePKIMismatch        = errors.New("certificate database and PKI identities do not match")
	ErrCertificateCommand            = errors.New("certificate revocation command failed")
	ErrCertificateCRL                = errors.New("certificate revocation list generation failed")
	ErrCertificateIndexCompatibility = errors.New(
		"certificate legacy index metadata normalization failed",
	)
	ErrCertificateDownloadBlocked = errors.New("certificate configuration download is blocked")
	ErrCertificateTOTPQRBlocked   = errors.New("certificate TOTP QR code view is blocked")
	ErrCertificateRenewal         = errors.New("certificate renewal failed")
)

var (
	certificateCommonNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)
	certificateSerialPatternSafe = regexp.MustCompile(`^[0-9A-Fa-f]{1,128}$`)
	auditErrorSummaryPattern     = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	auditRequestIDPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	auditTargetIDPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@:-]{0,127}$`)
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
	TFAName            string
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

type RenewCertificateResult struct {
	AlreadyRenewed   bool
	NewCertificateID int64
	CommonName       string
	StaticIP         string
	PreviousSerial   string
}

type CertificateDownloadExecutor func(CertificateState) error

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
	timeout time.Duration
}

func (d managementLifecycleDisconnector) Disconnect(
	ctx context.Context,
	commonName string,
) (bool, error) {
	statusResponse, err := d.execute(ctx, "status 2")
	if err != nil {
		return false, err
	}
	status, err := mi.ParseStatus(statusResponse)
	if err != nil {
		return false, err
	}
	for _, connectedClient := range status.ClientList {
		if connectedClient != nil && connectedClient.CommonName == commonName {
			killResponse, err := d.execute(ctx, "kill "+commonName)
			if err != nil {
				return false, err
			}
			if _, err := mi.ParseKillSession(killResponse); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

func (d managementLifecycleDisconnector) execute(
	ctx context.Context,
	command string,
) (string, error) {
	timeout := d.timeout
	if timeout <= 0 {
		timeout = defaultManagementTimeout
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	connection, err := (&net.Dialer{}).DialContext(
		commandContext,
		d.network,
		d.address,
	)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	if deadline, ok := commandContext.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return "", err
		}
	}
	stopCancellation := context.AfterFunc(commandContext, func() {
		_ = connection.Close()
	})
	defer stopCancellation()

	reader := bufio.NewReader(connection)
	if _, err := reader.ReadString('\n'); err != nil {
		return "", err
	}
	if err := mi.SendCommand(connection, command); err != nil {
		return "", err
	}
	return mi.ReadResponse(reader)
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
	protectedSerials     map[string]struct{}
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
	protectedSerials := make(map[string]struct{})
	for _, commonName := range config.ProtectedCommonNames {
		commonName = strings.TrimSpace(commonName)
		if commonName != "" {
			protected[strings.ToLower(commonName)] = struct{}{}
		}
	}
	caPath := filepath.Join(pkiDir, "ca.crt")
	caSerial, caCommonName, err := readCertificateIdentity(caPath)
	switch {
	case err == nil:
		protected[strings.ToLower(caCommonName)] = struct{}{}
		protectedSerials[normalizeCertificateSerial(caSerial)] = struct{}{}
	case errors.Is(err, os.ErrNotExist):
		// A new isolated PKI may initialize after the UI starts.
	default:
		return nil, fmt.Errorf("read certificate authority identity: %w", err)
	}

	return &CertificateLifecycleService{
		db:                   db,
		easyRSABinary:        easyRSABinary,
		easyRSAWorkingDir:    easyRSAWorkingDir,
		pkiDir:               pkiDir,
		indexPath:            filepath.Join(pkiDir, "index.txt"),
		crlPath:              filepath.Join(pkiDir, "crl.pem"),
		protectedCommonNames: protected,
		protectedSerials:     protectedSerials,
		runner:               osLifecycleCommandRunner{},
		disconnector: managementLifecycleDisconnector{
			network: config.ManagementNetwork,
			address: config.ManagementAddress,
			timeout: defaultManagementTimeout,
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

func (s *CertificateLifecycleService) isProtectedCertificate(
	commonName string,
	serialNumber string,
) bool {
	if s.IsProtectedCommonName(commonName) {
		return true
	}
	_, protected := s.protectedSerials[normalizeCertificateSerial(serialNumber)]
	return protected
}

func (s *CertificateLifecycleService) SyncCertificateMetadata(
	ctx context.Context,
) (CertificateImportResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.syncCertificateMetadataLocked(ctx)
}

// SyncCreatedCertificateMetadata imports the read-only Easy-RSA index and
// attaches database-owned static IP and non-secret TOTP identity metadata.
// TOTP seeds remain exclusively in the existing oath.secrets workflow.
func (s *CertificateLifecycleService) SyncCreatedCertificateMetadata(
	ctx context.Context,
	commonName string,
	staticIP string,
	tfaName string,
	issuer string,
) (CertificateImportResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.syncCertificateMetadataLocked(ctx)
	if err != nil {
		return result, err
	}
	commonName = strings.TrimSpace(commonName)
	staticIP = strings.TrimSpace(staticIP)
	tfaName = strings.TrimSpace(tfaName)
	if !ValidateCertificateCommonName(commonName) {
		return result, errors.New("invalid created certificate identity metadata")
	}
	staticIPValue := any(nil)
	if staticIP != "" {
		parsedIP := net.ParseIP(staticIP)
		if parsedIP == nil ||
			parsedIP.To4() == nil ||
			parsedIP.To4().String() != staticIP {
			return result, errors.New("invalid created certificate static IP metadata")
		}
		staticIPValue = staticIP
	}
	if (tfaName != "" && !ValidateCertificateCommonName(tfaName)) ||
		len(issuer) > 128 ||
		strings.ContainsAny(issuer, "\x00\r\n") {
		return result, errors.New("invalid 2FA identity metadata")
	}

	currentSerial, err := s.currentIssuedCertificateSerial(commonName)
	if err != nil {
		return result, fmt.Errorf("read created certificate identity: %w", err)
	}
	certificateID, err := s.certificateIDBySerial(ctx, currentSerial)
	if err != nil {
		return result, fmt.Errorf("read created certificate database ID: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, fmt.Errorf("begin created certificate metadata update: %w", err)
	}
	defer tx.Rollback()

	updateResult, err := tx.ExecContext(
		ctx,
		`UPDATE certificates
		SET static_ip = ?
		WHERE id = ? AND common_name = ?
			AND status IN ('valid', 'expired')
			AND archived_at IS NULL`,
		staticIPValue,
		certificateID,
		commonName,
	)
	if err != nil {
		return result, fmt.Errorf("update created certificate metadata: %w", err)
	}
	rowsAffected, err := updateResult.RowsAffected()
	if err != nil || rowsAffected != 1 {
		return result, errors.New("created certificate metadata target was not updated")
	}
	if tfaName != "" {
		if err := upsertTOTPIdentityMetadata(
			ctx,
			tx,
			certificateID,
			tfaName,
			issuer,
			s.now().UTC(),
		); err != nil {
			return result, fmt.Errorf(
				"update created certificate 2FA identity metadata: %w",
				err,
			)
		}
	}
	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("commit created certificate metadata: %w", err)
	}
	return result, nil
}

func (s *CertificateLifecycleService) syncCertificateMetadataLocked(
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
		c.id, c.common_name, c.serial_number, c.status, c.static_ip,
		c.technical_expires_at, c.revoked_at, c.archived_at,
		t.tfa_name
	FROM certificates AS c
	LEFT JOIN totp_identities AS t ON t.certificate_id = c.id
	WHERE c.archived_at `+operator+`
	ORDER BY c.common_name, c.id`)
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
		state.Protected = s.isProtectedCertificate(
			state.CommonName,
			state.SerialNumber,
		)
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
	return s.downloadableCertificateLocked(ctx, certificateID)
}

func (s *CertificateLifecycleService) IsCurrentIssuedCertificate(
	ctx context.Context,
	certificateID int64,
) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.loadCertificate(ctx, certificateID)
	if err != nil {
		return false, err
	}
	if !ValidateCertificateCommonName(state.CommonName) ||
		!ValidateCertificateSerial(state.SerialNumber) {
		return false, ErrCertificateIdentity
	}
	matches, err := s.certificateFileMatchesState(
		filepath.Join(s.pkiDir, "issued", state.CommonName+".crt"),
		state,
	)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return matches, err
}

func (s *CertificateLifecycleService) downloadableCertificateLocked(
	ctx context.Context,
	certificateID int64,
) (CertificateState, error) {
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
	matchesCurrent, err := s.certificateFileMatchesState(
		filepath.Join(s.pkiDir, "issued", state.CommonName+".crt"),
		state,
	)
	if err != nil || !matchesCurrent {
		return CertificateState{}, ErrCertificateDownloadBlocked
	}
	return state, nil
}

// PerformCertificateDownload keeps validation, configuration generation,
// response delivery, and audit under the lifecycle mutex. A concurrent revoke,
// archive, or renewal therefore cannot begin after validation but before the
// selected certificate has been delivered.
func (s *CertificateLifecycleService) PerformCertificateDownload(
	ctx context.Context,
	certificateID int64,
	actor CertificateLifecycleActor,
	executor CertificateDownloadExecutor,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !actor.IsAdmin {
		return s.auditFailure(
			ctx,
			actor,
			auditActionDownload,
			certificateID,
			"permission_denied",
			ErrCertificateForbidden,
		)
	}
	state, err := s.downloadableCertificateLocked(ctx, certificateID)
	if err != nil {
		_ = s.recordAudit(
			ctx,
			s.db,
			actor,
			auditActionDownload,
			certificateID,
			"certificate configuration download",
			"failed",
			"download_blocked",
		)
		return err
	}
	if err := s.recordAudit(
		ctx,
		s.db,
		actor,
		auditActionDownload,
		certificateID,
		"certificate configuration download",
		CertificateAuditResultStarted,
		"",
	); err != nil {
		return err
	}
	if executor == nil {
		err = errors.New("certificate download executor is nil")
	} else {
		err = executor(state)
	}
	if err != nil {
		_ = s.recordAudit(
			ctx,
			s.db,
			actor,
			auditActionDownload,
			certificateID,
			"certificate configuration download",
			"failed",
			"download_failed",
		)
		return err
	}
	return s.recordAudit(
		ctx,
		s.db,
		actor,
		auditActionDownload,
		certificateID,
		"certificate configuration download",
		"success",
		"",
	)
}

// PerformCertificateTOTPQRCodeView keeps authorization, name confirmation,
// lifecycle validation, image delivery, and auditing under the same mutex.
func (s *CertificateLifecycleService) PerformCertificateTOTPQRCodeView(
	ctx context.Context,
	certificateID int64,
	confirmation string,
	actor CertificateLifecycleActor,
	executor CertificateDownloadExecutor,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !actor.IsAdmin {
		return s.auditFailure(
			ctx,
			actor,
			auditActionTOTPQR,
			certificateID,
			"permission_denied",
			ErrCertificateForbidden,
		)
	}
	state, err := s.downloadableCertificateLocked(ctx, certificateID)
	if err != nil || state.TFAName == "" {
		_ = s.recordAudit(
			ctx,
			s.db,
			actor,
			auditActionTOTPQR,
			certificateID,
			"certificate TOTP QR code view",
			"failed",
			"qr_blocked",
		)
		if err != nil {
			return err
		}
		return ErrCertificateTOTPQRBlocked
	}
	if !constantTimeStringEqual(confirmation, state.CommonName) {
		return s.auditFailure(
			ctx,
			actor,
			auditActionTOTPQR,
			certificateID,
			"confirmation_mismatch",
			ErrCertificateConfirmation,
		)
	}
	if err := s.recordAudit(
		ctx,
		s.db,
		actor,
		auditActionTOTPQR,
		certificateID,
		"certificate TOTP QR code view",
		CertificateAuditResultStarted,
		"",
	); err != nil {
		return err
	}
	if executor == nil {
		err = errors.New("certificate TOTP QR code executor is nil")
	} else {
		err = executor(state)
	}
	if err != nil {
		_ = s.recordAudit(
			ctx,
			s.db,
			actor,
			auditActionTOTPQR,
			certificateID,
			"certificate TOTP QR code view",
			"failed",
			"qr_delivery_failed",
		)
		return err
	}
	return s.recordAudit(
		ctx,
		s.db,
		actor,
		auditActionTOTPQR,
		certificateID,
		"certificate TOTP QR code view",
		"success",
		"",
	)
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
	if state.Protected {
		return ArchiveCertificateResult{}, s.auditFailure(
			ctx,
			actor,
			auditActionArchive,
			certificateID,
			"invalid_identity",
			ErrCertificateIdentity,
		)
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

func (s *CertificateLifecycleService) RenewCertificate(
	ctx context.Context,
	certificateID int64,
	actor CertificateLifecycleActor,
) (RenewCertificateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if certificateID <= 0 {
		return RenewCertificateResult{}, s.auditFailure(
			ctx,
			actor,
			CertificateAuditActionRenew,
			certificateID,
			"invalid_target",
			ErrCertificateNotFound,
		)
	}
	if !actor.IsAdmin {
		return RenewCertificateResult{}, s.auditFailure(
			ctx,
			actor,
			CertificateAuditActionRenew,
			certificateID,
			"permission_denied",
			ErrCertificateForbidden,
		)
	}

	state, err := s.loadCertificate(ctx, certificateID)
	if err != nil {
		return RenewCertificateResult{}, s.auditFailure(
			ctx,
			actor,
			CertificateAuditActionRenew,
			certificateID,
			"not_found",
			err,
		)
	}
	if state.ArchivedAt != nil ||
		(state.Status != "valid" && state.Status != "expired") {
		return RenewCertificateResult{}, s.auditFailure(
			ctx,
			actor,
			CertificateAuditActionRenew,
			certificateID,
			"invalid_state",
			ErrCertificateInvalidState,
		)
	}
	if !ValidateCertificateCommonName(state.CommonName) ||
		!ValidateCertificateSerial(state.SerialNumber) ||
		state.Protected {
		return RenewCertificateResult{}, s.auditFailure(
			ctx,
			actor,
			CertificateAuditActionRenew,
			certificateID,
			"invalid_identity",
			ErrCertificateIdentity,
		)
	}

	pkiRecord, err := s.loadPKICertificate(state.SerialNumber)
	if err != nil || pkiRecord.CommonName != state.CommonName {
		return RenewCertificateResult{}, s.auditFailure(
			ctx,
			actor,
			CertificateAuditActionRenew,
			certificateID,
			"pki_identity_mismatch",
			ErrCertificatePKIMismatch,
		)
	}
	if pkiRecord.Status != "valid" && pkiRecord.Status != "expired" {
		return RenewCertificateResult{}, s.auditFailure(
			ctx,
			actor,
			CertificateAuditActionRenew,
			certificateID,
			"pki_invalid_state",
			ErrCertificateInvalidState,
		)
	}

	currentSerial, err := s.currentIssuedCertificateSerial(state.CommonName)
	if err != nil {
		return RenewCertificateResult{}, s.auditFailure(
			ctx,
			actor,
			CertificateAuditActionRenew,
			certificateID,
			"issued_certificate_read_failed",
			ErrCertificatePKIMismatch,
		)
	}
	if normalizeCertificateSerial(currentSerial) !=
		normalizeCertificateSerial(state.SerialNumber) {
		alreadyRenewed, newCertificateID := s.completedRenewalState(
			ctx,
			state,
			currentSerial,
		)
		if !alreadyRenewed {
			return RenewCertificateResult{}, s.auditFailure(
				ctx,
				actor,
				CertificateAuditActionRenew,
				certificateID,
				"issued_certificate_mismatch",
				ErrCertificatePKIMismatch,
			)
		}
		if _, err := s.syncCertificateMetadataLocked(ctx); err != nil {
			return RenewCertificateResult{}, s.auditFailure(
				ctx,
				actor,
				CertificateAuditActionRenew,
				certificateID,
				"metadata_sync_failed",
				ErrCertificateRenewal,
			)
		}
		newCertificateID, err = s.certificateIDBySerial(ctx, currentSerial)
		if err != nil {
			return RenewCertificateResult{}, s.auditFailure(
				ctx,
				actor,
				CertificateAuditActionRenew,
				certificateID,
				"metadata_lookup_failed",
				ErrCertificateRenewal,
			)
		}
		if err := s.transferRenewedCertificateMetadata(
			ctx,
			certificateID,
			newCertificateID,
		); err != nil {
			return RenewCertificateResult{}, s.auditFailure(
				ctx,
				actor,
				CertificateAuditActionRenew,
				certificateID,
				"renewal_metadata_transfer_failed",
				ErrCertificateRenewal,
			)
		}
		if err := s.recordAudit(
			ctx,
			s.db,
			actor,
			CertificateAuditActionRenew,
			certificateID,
			"certificate renewal",
			"already_renewed",
			"",
		); err != nil {
			return RenewCertificateResult{}, err
		}
		return RenewCertificateResult{
			AlreadyRenewed:   true,
			NewCertificateID: newCertificateID,
			CommonName:       state.CommonName,
			StaticIP:         state.StaticIP,
			PreviousSerial:   state.SerialNumber,
		}, nil
	}

	if err := s.recordAudit(
		ctx,
		s.db,
		actor,
		CertificateAuditActionRenew,
		certificateID,
		"certificate renewal",
		CertificateAuditResultStarted,
		"",
	); err != nil {
		return RenewCertificateResult{}, err
	}
	if err := s.runEasyRSA(
		ctx,
		[]string{
			"--batch",
			"--pki-dir=" + s.pkiDir,
			"renew",
			state.CommonName,
		},
	); err != nil {
		return RenewCertificateResult{}, s.auditFailure(
			ctx,
			actor,
			CertificateAuditActionRenew,
			certificateID,
			"renewal_command_failed",
			ErrCertificateRenewal,
		)
	}

	newSerial, err := s.currentIssuedCertificateSerial(state.CommonName)
	if err != nil ||
		normalizeCertificateSerial(newSerial) ==
			normalizeCertificateSerial(state.SerialNumber) {
		return RenewCertificateResult{}, s.auditFailure(
			ctx,
			actor,
			CertificateAuditActionRenew,
			certificateID,
			"renewal_verification_failed",
			ErrCertificatePKIMismatch,
		)
	}
	newRecord, err := s.loadPKICertificate(newSerial)
	if err != nil ||
		newRecord.CommonName != state.CommonName ||
		newRecord.Status != "valid" {
		return RenewCertificateResult{}, s.auditFailure(
			ctx,
			actor,
			CertificateAuditActionRenew,
			certificateID,
			"renewal_verification_failed",
			ErrCertificatePKIMismatch,
		)
	}
	if _, err := s.syncCertificateMetadataLocked(ctx); err != nil {
		return RenewCertificateResult{}, s.auditFailure(
			ctx,
			actor,
			CertificateAuditActionRenew,
			certificateID,
			"metadata_sync_failed",
			ErrCertificateRenewal,
		)
	}
	newCertificateID, err := s.certificateIDBySerial(ctx, newSerial)
	if err != nil {
		return RenewCertificateResult{}, s.auditFailure(
			ctx,
			actor,
			CertificateAuditActionRenew,
			certificateID,
			"metadata_lookup_failed",
			ErrCertificateRenewal,
		)
	}
	if err := s.transferRenewedCertificateMetadata(
		ctx,
		certificateID,
		newCertificateID,
	); err != nil {
		return RenewCertificateResult{}, s.auditFailure(
			ctx,
			actor,
			CertificateAuditActionRenew,
			certificateID,
			"renewal_metadata_transfer_failed",
			ErrCertificateRenewal,
		)
	}
	if err := s.recordAudit(
		ctx,
		s.db,
		actor,
		CertificateAuditActionRenew,
		certificateID,
		"certificate renewal",
		"success",
		"",
	); err != nil {
		return RenewCertificateResult{}, err
	}
	return RenewCertificateResult{
		NewCertificateID: newCertificateID,
		CommonName:       state.CommonName,
		StaticIP:         state.StaticIP,
		PreviousSerial:   state.SerialNumber,
	}, nil
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
		state.Protected {
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
	if pkiRecord.Status != "revoked" &&
		pkiRecord.Status != "valid" &&
		pkiRecord.Status != "expired" {
		return RevokeCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionRevoke, certificateID, "pki_invalid_state",
			ErrCertificateInvalidState,
		)
	}
	if err := s.recordAudit(
		ctx,
		s.db,
		actor,
		auditActionRevoke,
		certificateID,
		"certificate revocation",
		CertificateAuditResultStarted,
		"",
	); err != nil {
		return RevokeCertificateResult{}, err
	}

	if pkiRecord.Status != "revoked" {
		revokeCommand, err := s.resolveRevokeCommand(state)
		if err != nil {
			return RevokeCertificateResult{}, s.auditFailure(
				ctx,
				actor,
				auditActionRevoke,
				certificateID,
				"revoke_target_mismatch",
				ErrCertificatePKIMismatch,
			)
		}
		if _, err := s.normalizeLegacyIndexMetadata(
			state,
			revokeCommand,
		); err != nil {
			return RevokeCertificateResult{}, s.auditFailure(
				ctx,
				actor,
				auditActionRevoke,
				certificateID,
				"index_compatibility_failed",
				ErrCertificateIndexCompatibility,
			)
		}
		if err := s.runEasyRSA(
			ctx,
			[]string{
				"--batch",
				"--pki-dir=" + s.pkiDir,
				revokeCommand,
				state.CommonName,
			},
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
	crlInfo, err := os.Lstat(s.crlPath)
	if err != nil || !crlInfo.Mode().IsRegular() {
		return RevokeCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionRevoke, certificateID, "crl_verification_failed",
			ErrCertificateCRL,
		)
	}
	// Easy-RSA creates a new CRL with mode 0600 when no previous file exists.
	// The OpenVPN server drops privileges to nobody/nogroup and must be able to
	// read the public CRL for every new connection.
	if err := os.Chmod(s.crlPath, 0o644); err != nil {
		return RevokeCertificateResult{}, s.auditFailure(
			ctx, actor, auditActionRevoke, certificateID, "crl_permission_failed",
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

	hasActiveSuccessor := false
	if state.StaticIP != "" {
		if err := tx.QueryRowContext(
			ctx,
			`SELECT EXISTS(
				SELECT 1 FROM certificates
				WHERE id <> ?
					AND static_ip = ?
					AND status = 'valid'
					AND archived_at IS NULL
			)`,
			certificateID,
			state.StaticIP,
		).Scan(&hasActiveSuccessor); err != nil {
			_ = tx.Rollback()
			return RevokeCertificateResult{}, s.auditFailure(
				ctx,
				actor,
				auditActionRevoke,
				certificateID,
				"ip_allocation_check_failed",
				err,
			)
		}
	}
	if state.StaticIP != "" && !hasActiveSuccessor {
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

func (s *CertificateLifecycleService) resolveRevokeCommand(
	state CertificateState,
) (string, error) {
	currentMatches, currentErr := s.certificateFileMatchesState(
		filepath.Join(s.pkiDir, "issued", state.CommonName+".crt"),
		state,
	)
	if currentErr != nil && !errors.Is(currentErr, os.ErrNotExist) {
		return "", currentErr
	}
	renewedMatches, renewedErr := s.certificateFileMatchesState(
		filepath.Join(s.pkiDir, "renewed", "issued", state.CommonName+".crt"),
		state,
	)
	if renewedErr != nil && !errors.Is(renewedErr, os.ErrNotExist) {
		return "", renewedErr
	}
	switch {
	case currentMatches && !renewedMatches:
		return "revoke", nil
	case renewedMatches && !currentMatches:
		return "revoke-renewed", nil
	default:
		return "", ErrCertificatePKIMismatch
	}
}

func (s *CertificateLifecycleService) completedRenewalState(
	ctx context.Context,
	state CertificateState,
	currentSerial string,
) (bool, int64) {
	currentRecord, err := s.loadPKICertificate(currentSerial)
	if err != nil ||
		currentRecord.CommonName != state.CommonName ||
		currentRecord.Status != "valid" {
		return false, 0
	}
	renewedMatches, err := s.certificateFileMatchesState(
		filepath.Join(s.pkiDir, "renewed", "issued", state.CommonName+".crt"),
		state,
	)
	if err != nil || !renewedMatches {
		return false, 0
	}
	certificateID, _ := s.certificateIDBySerial(ctx, currentSerial)
	return true, certificateID
}

func (s *CertificateLifecycleService) currentIssuedCertificateSerial(
	commonName string,
) (string, error) {
	serial, certificateCommonName, err := readCertificateIdentity(
		filepath.Join(s.pkiDir, "issued", commonName+".crt"),
	)
	if err != nil {
		return "", err
	}
	if certificateCommonName != commonName {
		return "", ErrCertificatePKIMismatch
	}
	return serial, nil
}

func (s *CertificateLifecycleService) certificateFileMatchesState(
	path string,
	state CertificateState,
) (bool, error) {
	serial, commonName, err := readCertificateIdentity(path)
	if err != nil {
		return false, err
	}
	return commonName == state.CommonName &&
		normalizeCertificateSerial(serial) ==
			normalizeCertificateSerial(state.SerialNumber), nil
}

func readCertificateIdentity(path string) (string, string, error) {
	certificate, err := readCertificate(path)
	if err != nil {
		return "", "", err
	}
	return strings.ToUpper(certificate.SerialNumber.Text(16)),
		certificate.Subject.CommonName,
		nil
}

func readCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("certificate file does not contain a PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if certificate.SerialNumber == nil || certificate.SerialNumber.Sign() < 0 {
		return nil, errors.New("certificate file has an invalid serial number")
	}
	return certificate, nil
}

func normalizeCertificateSerial(serial string) string {
	normalized := strings.TrimLeft(strings.ToUpper(strings.TrimSpace(serial)), "0")
	if normalized == "" {
		return "0"
	}
	return normalized
}

func (s *CertificateLifecycleService) certificateIDBySerial(
	ctx context.Context,
	serial string,
) (int64, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT id, serial_number FROM certificates`,
	)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	normalizedSerial := normalizeCertificateSerial(serial)
	for rows.Next() {
		var certificateID int64
		var storedSerial string
		if err := rows.Scan(&certificateID, &storedSerial); err != nil {
			return 0, err
		}
		if normalizeCertificateSerial(storedSerial) == normalizedSerial {
			return certificateID, nil
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	return 0, sql.ErrNoRows
}

func (s *CertificateLifecycleService) transferRenewedCertificateMetadata(
	ctx context.Context,
	previousCertificateID int64,
	newCertificateID int64,
) error {
	if previousCertificateID <= 0 ||
		newCertificateID <= 0 ||
		previousCertificateID == newCertificateID {
		return errors.New("invalid renewed certificate metadata transfer")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(
		ctx,
		`UPDATE certificates
		SET
			vpn_user_id = (
				SELECT vpn_user_id FROM certificates WHERE id = ?
			),
			permission_type = (
				SELECT permission_type FROM certificates WHERE id = ?
			),
			static_ip = (
				SELECT static_ip FROM certificates WHERE id = ?
			),
			validity_mode = (
				SELECT validity_mode FROM certificates WHERE id = ?
			),
			business_expires_at = (
				SELECT business_expires_at FROM certificates WHERE id = ?
			),
			device_note = (
				SELECT device_note FROM certificates WHERE id = ?
			)
		WHERE id = ?`,
		previousCertificateID,
		previousCertificateID,
		previousCertificateID,
		previousCertificateID,
		previousCertificateID,
		previousCertificateID,
		newCertificateID,
	)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected != 1 {
		return errors.New("renewed certificate metadata target was not updated")
	}

	if _, err := tx.ExecContext(
		ctx,
		`UPDATE totp_identities
		SET certificate_id = ?
		WHERE certificate_id = ?`,
		newCertificateID,
		previousCertificateID,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE ip_allocations
		SET certificate_id = ?
		WHERE certificate_id = ? AND status = 'allocated'`,
		newCertificateID,
		previousCertificateID,
	); err != nil {
		return err
	}
	return tx.Commit()
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
	normalizedSerial := normalizeCertificateSerial(serialNumber)
	for _, record := range records {
		if normalizeCertificateSerial(record.SerialNumber) == normalizedSerial {
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
		c.id, c.common_name, c.serial_number, c.status, c.static_ip,
		c.technical_expires_at, c.revoked_at, c.archived_at,
		t.tfa_name
	FROM certificates AS c
	LEFT JOIN totp_identities AS t ON t.certificate_id = c.id
	WHERE c.id = ?`, certificateID)
	state, err := scanCertificateState(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return CertificateState{}, ErrCertificateNotFound
	}
	if err != nil {
		return CertificateState{}, fmt.Errorf("read certificate lifecycle state: %w", err)
	}
	state.Protected = s.isProtectedCertificate(
		state.CommonName,
		state.SerialNumber,
	)
	return state, nil
}

type rowScanner func(...any) error

func scanCertificateState(scan rowScanner) (CertificateState, error) {
	var state CertificateState
	var staticIP sql.NullString
	var tfaName sql.NullString
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
		&tfaName,
	); err != nil {
		return CertificateState{}, err
	}
	if staticIP.Valid {
		state.StaticIP = staticIP.String
	}
	if tfaName.Valid {
		state.TFAName = tfaName.String
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

func (s *CertificateLifecycleService) RecordCertificateOperationAudit(
	ctx context.Context,
	actor CertificateLifecycleActor,
	action string,
	targetID string,
	result string,
	errorSummary string,
) error {
	summary, validAction := map[string]string{
		CertificateAuditActionArchive:  "certificate archive",
		CertificateAuditActionCreate:   "certificate creation",
		CertificateAuditActionDownload: "certificate configuration download",
		CertificateAuditActionReload:   "OpenVPN configuration reload",
		CertificateAuditActionRenew:    "certificate renewal",
		CertificateAuditActionRestart:  "OpenVPN restart",
		CertificateAuditActionRevoke:   "certificate revocation",
		CertificateAuditActionTOTPQR:   "certificate TOTP QR code view",
	}[action]
	if !validAction {
		return errors.New("invalid certificate audit action")
	}
	switch result {
	case CertificateAuditResultStarted, "success", "success_with_warning", "failed":
	default:
		return errors.New("invalid certificate audit result")
	}
	if errorSummary != "" &&
		!auditErrorSummaryPattern.MatchString(errorSummary) {
		return errors.New("invalid certificate audit error summary")
	}
	return s.recordAuditTarget(
		ctx,
		s.db,
		actor,
		action,
		normalizeAuditTargetID(targetID),
		summary,
		result,
		errorSummary,
	)
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
	return s.recordAuditTarget(
		ctx,
		executor,
		actor,
		action,
		strconv.FormatInt(certificateID, 10),
		summary,
		result,
		errorSummary,
	)
}

func (s *CertificateLifecycleService) recordAuditTarget(
	ctx context.Context,
	executor auditExecutor,
	actor CertificateLifecycleActor,
	action string,
	targetID string,
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
		targetID,
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

func normalizeAuditTargetID(targetID string) string {
	targetID = strings.TrimSpace(targetID)
	if targetID == "" {
		return ""
	}
	if len(targetID) > 128 ||
		!auditTargetIDPattern.MatchString(targetID) {
		return "unavailable"
	}
	return targetID
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
