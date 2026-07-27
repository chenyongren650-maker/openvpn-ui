package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/d3vilh/openvpn-ui/lib"
)

const (
	UserCertificateAuditActionProvision = "vpn_user_certificate.provision"

	userCertificateAuditTargetType = "vpn_user_certificate"
	defaultTFAIssuer               = "ZHISUAN"
)

var (
	ErrUserProvisioningForbidden = errors.New(
		"VPN user certificate provisioning requires administrator permission",
	)
	ErrUserProvisioningInvalidInput = errors.New(
		"VPN user certificate provisioning input is invalid",
	)
	ErrUserProvisioningConflict = errors.New(
		"VPN user certificate provisioning conflicts with existing state",
	)
	ErrUserProvisioningRecoveryRequired = errors.New(
		"VPN user certificate provisioning requires recovery",
	)
	ErrUserProvisioningAuditUnavailable = errors.New(
		"VPN user certificate provisioning audit storage is unavailable",
	)

	vpnUsernamePattern = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`,
	)
)

type UserCertificateProvisioningInput struct {
	DisplayName     string
	Username        string
	Email           string
	Department      string
	CertificateName string
	TFAName         string
	TFAIssuer       string
	PermissionType  string
	ExpireDays      string
	DeviceNote      string
	BusinessNote    string
	Passphrase      string
	Country         string
	Province        string
	City            string
	Org             string
	OrgUnit         string
}

type UserCertificateProvisioningResult struct {
	VPNUserID        int64
	CertificateID    int64
	CertificateName  string
	PermissionType   string
	StaticIP         string
	RecoveryRequired bool
	Retried          bool
}

type CertificateCreationExecutor interface {
	CreateCertificate(lib.CertificateCreationRequest) error
}

type CertificateCreationExecutorFunc func(lib.CertificateCreationRequest) error

func (f CertificateCreationExecutorFunc) CreateCertificate(
	request lib.CertificateCreationRequest,
) error {
	return f(request)
}

type CreatedCertificateMetadataSynchronizer interface {
	SyncCreatedCertificateMetadata(
		context.Context,
		string,
		string,
		string,
		string,
	) (CertificateImportResult, error)
}

type UserCertificateProvisioningService struct {
	db        *sql.DB
	allocator *RestrictedIPAllocationService
	creator   CertificateCreationExecutor
	syncer    CreatedCertificateMetadataSynchronizer
	now       func() time.Time
}

func NewUserCertificateProvisioningService(
	db *sql.DB,
	allocator *RestrictedIPAllocationService,
	creator CertificateCreationExecutor,
	syncer CreatedCertificateMetadataSynchronizer,
) (*UserCertificateProvisioningService, error) {
	if db == nil {
		return nil, errors.New("VPN user provisioning database is nil")
	}
	if allocator == nil {
		return nil, errors.New("restricted IP allocation service is nil")
	}
	if creator == nil {
		return nil, errors.New("certificate creation executor is nil")
	}
	if syncer == nil {
		return nil, errors.New("certificate metadata synchronizer is nil")
	}
	return &UserCertificateProvisioningService{
		db:        db,
		allocator: allocator,
		creator:   creator,
		syncer:    syncer,
		now:       func() time.Time { return time.Now().UTC() },
	}, nil
}

func (s *UserCertificateProvisioningService) Provision(
	ctx context.Context,
	input UserCertificateProvisioningInput,
	actor CertificateLifecycleActor,
) (UserCertificateProvisioningResult, error) {
	input = normalizeProvisioningInput(input)
	result := UserCertificateProvisioningResult{
		CertificateName: input.CertificateName,
		PermissionType:  input.PermissionType,
	}

	if !actor.IsAdmin || actor.UserID <= 0 {
		_ = s.recordProvisioningAudit(
			ctx,
			s.db,
			actor,
			input.CertificateName,
			0,
			input.PermissionType,
			"",
			"failed",
			"permission_denied",
		)
		return result, ErrUserProvisioningForbidden
	}
	if !auditRequestIDPattern.MatchString(actor.RequestID) {
		return result, ErrUserProvisioningInvalidInput
	}
	if err := s.recordProvisioningAudit(
		ctx,
		s.db,
		actor,
		input.CertificateName,
		0,
		input.PermissionType,
		"",
		CertificateAuditResultStarted,
		"",
	); err != nil {
		return result, errors.Join(
			ErrUserProvisioningAuditUnavailable,
			err,
		)
	}

	certificateRequest, err := validateAndBuildProvisioningRequest(input)
	if err != nil {
		return result, s.auditProvisioningFailure(
			ctx,
			actor,
			input.CertificateName,
			0,
			input.PermissionType,
			"",
			"invalid_input",
			ErrUserProvisioningInvalidInput,
		)
	}

	vpnUserID, userCreated, err := s.createOrMatchVPNUser(ctx, input)
	if err != nil {
		return result, s.auditProvisioningFailure(
			ctx,
			actor,
			input.CertificateName,
			0,
			input.PermissionType,
			"",
			"user_conflict",
			err,
		)
	}
	result.VPNUserID = vpnUserID

	var reservation RestrictedIPReservation
	if input.PermissionType == PermissionTypeRestricted {
		reservation, err = s.allocator.Reserve(
			ctx,
			input.CertificateName,
			actor.RequestID,
		)
		if err != nil {
			if userCreated {
				_ = s.deleteUnlinkedVPNUser(ctx, vpnUserID)
			}
			return result, s.auditProvisioningFailure(
				ctx,
				actor,
				input.CertificateName,
				vpnUserID,
				input.PermissionType,
				"",
				"ip_reservation_failed",
				err,
			)
		}
		result.StaticIP = reservation.IPAddress
		result.Retried = reservation.RequestID != actor.RequestID ||
			reservation.Status == "completed"
		certificateRequest.StaticIP = reservation.IPAddress
	}

	if err := s.creator.CreateCertificate(certificateRequest); err != nil {
		if errors.Is(err, lib.ErrCertificateCreationIncomplete) {
			s.markReservationRecovery(
				ctx,
				reservation.ID,
				"certificate_creation_incomplete",
			)
			result.RecoveryRequired = true
			return result, s.auditProvisioningFailure(
				ctx,
				actor,
				input.CertificateName,
				vpnUserID,
				input.PermissionType,
				result.StaticIP,
				"certificate_creation_incomplete",
				ErrUserProvisioningRecoveryRequired,
			)
		}
		if reservation.ID > 0 {
			_ = s.allocator.Release(ctx, reservation.ID, "certificate_creation_failed")
		}
		if userCreated {
			_ = s.deleteUnlinkedVPNUser(ctx, vpnUserID)
		}
		return result, s.auditProvisioningFailure(
			ctx,
			actor,
			input.CertificateName,
			vpnUserID,
			input.PermissionType,
			result.StaticIP,
			"certificate_creation_failed",
			err,
		)
	}

	if _, err := s.syncer.SyncCreatedCertificateMetadata(
		ctx,
		input.CertificateName,
		result.StaticIP,
		certificateRequest.TFAName,
		certificateRequest.TFAIssuer,
	); err != nil {
		s.markReservationRecovery(ctx, reservation.ID, "metadata_sync_failed")
		result.RecoveryRequired = true
		return result, s.auditProvisioningFailure(
			ctx,
			actor,
			input.CertificateName,
			vpnUserID,
			input.PermissionType,
			result.StaticIP,
			"metadata_sync_failed",
			ErrUserProvisioningRecoveryRequired,
		)
	}

	certificateID, err := s.commitProvisionedMetadata(
		ctx,
		input,
		actor,
		vpnUserID,
		reservation,
	)
	if err != nil {
		s.markReservationRecovery(ctx, reservation.ID, "database_commit_failed")
		result.RecoveryRequired = true
		return result, s.auditProvisioningFailure(
			ctx,
			actor,
			input.CertificateName,
			vpnUserID,
			input.PermissionType,
			result.StaticIP,
			"database_commit_failed",
			ErrUserProvisioningRecoveryRequired,
		)
	}
	result.CertificateID = certificateID
	return result, nil
}

func normalizeProvisioningInput(
	input UserCertificateProvisioningInput,
) UserCertificateProvisioningInput {
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.Username = strings.TrimSpace(input.Username)
	input.Email = strings.TrimSpace(input.Email)
	input.Department = strings.TrimSpace(input.Department)
	input.CertificateName = strings.TrimSpace(input.CertificateName)
	input.TFAName = strings.TrimSpace(input.TFAName)
	input.TFAIssuer = strings.TrimSpace(input.TFAIssuer)
	input.PermissionType = strings.TrimSpace(input.PermissionType)
	input.ExpireDays = strings.TrimSpace(input.ExpireDays)
	input.DeviceNote = strings.TrimSpace(input.DeviceNote)
	input.BusinessNote = strings.TrimSpace(input.BusinessNote)
	input.Country = strings.TrimSpace(input.Country)
	input.Province = strings.TrimSpace(input.Province)
	input.City = strings.TrimSpace(input.City)
	input.Org = strings.TrimSpace(input.Org)
	input.OrgUnit = strings.TrimSpace(input.OrgUnit)
	if input.PermissionType == "" {
		input.PermissionType = PermissionTypeNormal
	}
	if input.TFAName == "" {
		input.TFAName = input.Email
	}
	if input.TFAIssuer == "" {
		input.TFAIssuer = defaultTFAIssuer
	}
	return input
}

func validateAndBuildProvisioningRequest(
	input UserCertificateProvisioningInput,
) (lib.CertificateCreationRequest, error) {
	if !validProvisioningText(input.DisplayName, 128, true) ||
		!vpnUsernamePattern.MatchString(input.Username) ||
		!validProvisioningEmail(input.Email) ||
		!validProvisioningText(input.Department, 128, false) ||
		!ValidateCertificateCommonName(input.CertificateName) ||
		!validProvisioningText(input.DeviceNote, 512, false) ||
		!validProvisioningText(input.BusinessNote, 2048, false) ||
		(input.PermissionType != PermissionTypeNormal &&
			input.PermissionType != PermissionTypeRestricted) {
		return lib.CertificateCreationRequest{}, ErrUserProvisioningInvalidInput
	}

	request := lib.CertificateCreationRequest{
		Name:       input.CertificateName,
		Passphrase: input.Passphrase,
		ExpireDays: input.ExpireDays,
		Email:      input.Email,
		Country:    input.Country,
		Province:   input.Province,
		City:       input.City,
		Org:        input.Org,
		OrgUnit:    input.OrgUnit,
		TFAName:    input.TFAName,
		TFAIssuer:  input.TFAIssuer,
	}
	if err := lib.ValidateCertificateCreationRequest(request); err != nil {
		return lib.CertificateCreationRequest{}, ErrUserProvisioningInvalidInput
	}
	return request, nil
}

func validProvisioningText(value string, maximumLength int, required bool) bool {
	if required && value == "" {
		return false
	}
	if len(value) > maximumLength {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validProvisioningEmail(value string) bool {
	if value == "" || len(value) > 254 ||
		strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value
}

type vpnUserState struct {
	ID          int64
	DisplayName string
	Username    string
	Email       sql.NullString
	Department  string
	Status      string
	Notes       string
}

func (s *UserCertificateProvisioningService) createOrMatchVPNUser(
	ctx context.Context,
	input UserCertificateProvisioningInput,
) (int64, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()

	existing, found, err := loadVPNUserByUsername(ctx, tx, input.Username)
	if err != nil {
		return 0, false, err
	}
	if found {
		if !vpnUserMatchesInput(existing, input) {
			return 0, false, ErrUserProvisioningConflict
		}
		if err := tx.Commit(); err != nil {
			return 0, false, err
		}
		return existing.ID, false, nil
	}

	var emailOwnerID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM vpn_users
		WHERE email = ? COLLATE NOCASE
			AND email IS NOT NULL AND trim(email) <> ''`,
		input.Email,
	).Scan(&emailOwnerID)
	if err == nil {
		return 0, false, ErrUserProvisioningConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, false, err
	}

	now := s.now().UTC()
	result, err := tx.ExecContext(ctx, `INSERT INTO vpn_users (
		display_name, username, email, department, status, notes,
		created_at, updated_at, archived_at
	) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, NULL)`,
		input.DisplayName,
		input.Username,
		input.Email,
		input.Department,
		input.BusinessNote,
		now,
		now,
	)
	if err != nil {
		return 0, false, ErrUserProvisioningConflict
	}
	vpnUserID, err := result.LastInsertId()
	if err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return vpnUserID, true, nil
}

func loadVPNUserByUsername(
	ctx context.Context,
	tx *sql.Tx,
	username string,
) (vpnUserState, bool, error) {
	var user vpnUserState
	err := tx.QueryRowContext(ctx, `SELECT
		id, display_name, username, email, department, status, notes
	FROM vpn_users WHERE username = ? COLLATE NOCASE`,
		username,
	).Scan(
		&user.ID,
		&user.DisplayName,
		&user.Username,
		&user.Email,
		&user.Department,
		&user.Status,
		&user.Notes,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return vpnUserState{}, false, nil
	}
	if err != nil {
		return vpnUserState{}, false, err
	}
	return user, true, nil
}

func vpnUserMatchesInput(
	user vpnUserState,
	input UserCertificateProvisioningInput,
) bool {
	return user.Status == "active" &&
		user.DisplayName == input.DisplayName &&
		strings.EqualFold(user.Username, input.Username) &&
		user.Email.Valid &&
		strings.EqualFold(user.Email.String, input.Email) &&
		user.Department == input.Department &&
		user.Notes == input.BusinessNote
}

func (s *UserCertificateProvisioningService) deleteUnlinkedVPNUser(
	ctx context.Context,
	vpnUserID int64,
) error {
	if vpnUserID <= 0 {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM vpn_users
		WHERE id = ?
			AND NOT EXISTS (
				SELECT 1 FROM certificates WHERE vpn_user_id = vpn_users.id
			)`,
		vpnUserID,
	)
	return err
}

func (s *UserCertificateProvisioningService) commitProvisionedMetadata(
	ctx context.Context,
	input UserCertificateProvisioningInput,
	actor CertificateLifecycleActor,
	vpnUserID int64,
	reservation RestrictedIPReservation,
) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var userStatus string
	if err := tx.QueryRowContext(
		ctx,
		`SELECT status FROM vpn_users WHERE id = ?`,
		vpnUserID,
	).Scan(&userStatus); err != nil {
		return 0, err
	}
	if userStatus != "active" {
		return 0, ErrUserProvisioningConflict
	}

	var certificateID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM certificates
		WHERE common_name = ?
			AND status IN ('valid', 'expired')
			AND archived_at IS NULL
		ORDER BY id DESC
		LIMIT 1`,
		input.CertificateName,
	).Scan(&certificateID); err != nil {
		return 0, err
	}

	staticIPValue := any(nil)
	if input.PermissionType == PermissionTypeRestricted {
		if reservation.ID <= 0 || reservation.IPAddress == "" ||
			!strings.EqualFold(
				reservation.CertificateName,
				input.CertificateName,
			) {
			return 0, ErrUserProvisioningConflict
		}
		staticIPValue = reservation.IPAddress
	}
	updateResult, err := tx.ExecContext(ctx, `UPDATE certificates
		SET vpn_user_id = ?,
			permission_type = ?,
			static_ip = ?,
			validity_mode = 'permanent',
			device_note = ?
		WHERE id = ?`,
		vpnUserID,
		input.PermissionType,
		staticIPValue,
		input.DeviceNote,
		certificateID,
	)
	if err != nil {
		return 0, err
	}
	rowsAffected, err := updateResult.RowsAffected()
	if err != nil || rowsAffected != 1 {
		return 0, ErrUserProvisioningConflict
	}

	if input.PermissionType == PermissionTypeRestricted {
		if err := s.allocator.completeReservationTx(
			ctx,
			tx,
			reservation.ID,
			certificateID,
		); err != nil {
			return 0, err
		}
	}
	if err := s.recordProvisioningAudit(
		ctx,
		tx,
		actor,
		input.CertificateName,
		vpnUserID,
		input.PermissionType,
		reservation.IPAddress,
		"success",
		"",
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return certificateID, nil
}

func (s *UserCertificateProvisioningService) markReservationRecovery(
	ctx context.Context,
	reservationID int64,
	errorSummary string,
) {
	if reservationID <= 0 {
		return
	}
	_ = s.allocator.MarkRecoveryRequired(ctx, reservationID, errorSummary)
}

func (s *UserCertificateProvisioningService) auditProvisioningFailure(
	ctx context.Context,
	actor CertificateLifecycleActor,
	certificateName string,
	vpnUserID int64,
	permissionType string,
	staticIP string,
	errorSummary string,
	operationError error,
) error {
	if err := s.recordProvisioningAudit(
		ctx,
		s.db,
		actor,
		certificateName,
		vpnUserID,
		permissionType,
		staticIP,
		"failed",
		errorSummary,
	); err != nil {
		return errors.Join(
			operationError,
			ErrUserProvisioningAuditUnavailable,
			err,
		)
	}
	return operationError
}

func (s *UserCertificateProvisioningService) recordProvisioningAudit(
	ctx context.Context,
	executor auditExecutor,
	actor CertificateLifecycleActor,
	certificateName string,
	vpnUserID int64,
	permissionType string,
	staticIP string,
	result string,
	errorSummary string,
) error {
	if executor == nil {
		return errors.New("provisioning audit executor is nil")
	}
	switch result {
	case CertificateAuditResultStarted, "success", "failed":
	default:
		return errors.New("invalid provisioning audit result")
	}
	if errorSummary != "" &&
		!auditErrorSummaryPattern.MatchString(errorSummary) {
		return errors.New("invalid provisioning audit error summary")
	}
	if !auditRequestIDPattern.MatchString(actor.RequestID) {
		return errors.New("invalid provisioning audit request ID")
	}
	targetID := normalizeAuditTargetID(certificateName)
	if permissionType != PermissionTypeNormal &&
		permissionType != PermissionTypeRestricted {
		permissionType = "invalid"
	}
	allocation := "dynamic"
	if permissionType == PermissionTypeRestricted && staticIP == "" {
		allocation = "pending"
	} else if staticIP != "" {
		allocation = staticIP
	}
	summary := "vpn_user_id=" + strconv.FormatInt(vpnUserID, 10) +
		" permission_type=" + permissionType +
		" allocation=" + allocation
	_, err := executor.ExecContext(ctx, `INSERT INTO audit_logs (
		actor_user_id, source_ip, action, target_type, target_id,
		summary, result, error_summary, request_id, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nullableActorUserID(actor.UserID),
		normalizeAuditSourceIP(actor.SourceIP),
		UserCertificateAuditActionProvision,
		userCertificateAuditTargetType,
		targetID,
		summary,
		result,
		errorSummary,
		actor.RequestID,
		s.now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("write VPN user provisioning audit: %w", err)
	}
	return nil
}
