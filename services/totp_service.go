package services

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	TOTPAuditActionQRCodeView = "totp.qr_view"
	TOTPAuditActionSecretView = "totp.secret_view"
	TOTPAuditActionVerify     = "totp.verify"
	TOTPAuditActionReset      = "totp.reset"

	defaultTOTPFailureLimit  = 5
	defaultTOTPFailureWindow = 5 * time.Minute
	defaultTOTPResetIssuer   = "ZHISUAN"

	totpResetStatusPrepared             = "prepared"
	totpResetStatusCompleted            = "completed"
	totpResetStatusFailed               = "failed"
	totpResetStatusCompensationRequired = "compensation_required"
)

var (
	ErrTOTPNotFound  = errors.New("TOTP identity was not found")
	ErrTOTPForbidden = errors.New(
		"TOTP operation requires administrator permission",
	)
	ErrTOTPInvalidState      = errors.New("TOTP identity state does not allow this operation")
	ErrTOTPConfirmation      = errors.New("certificate name confirmation does not match")
	ErrTOTPInvalidInput      = errors.New("TOTP request input is invalid")
	ErrTOTPSecretUnavailable = errors.New(
		"TOTP secret is unavailable",
	)
	ErrTOTPQRCodeUnavailable = errors.New(
		"TOTP QR code is unavailable",
	)
	ErrTOTPCodeInvalid   = errors.New("TOTP code is invalid")
	ErrTOTPCodeFormat    = errors.New("TOTP code format is invalid")
	ErrTOTPRateLimited   = errors.New("TOTP verification is rate limited")
	ErrTOTPResetConflict = errors.New(
		"another TOTP reset operation is already in progress",
	)
	ErrTOTPCompensationRequired = errors.New(
		"TOTP reset requires administrator recovery",
	)
	ErrTOTPAuditUnavailable = errors.New(
		"TOTP audit storage is unavailable",
	)

	totpCodePattern        = regexp.MustCompile(`^[0-9]{6}$`)
	totpIdempotencyPattern = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9._-]{15,127}$`,
	)
)

type TOTPServiceConfig struct {
	OATHSecretsPath string
	QRCodeDirectory string
	QRCodeBinary    string
	Issuer          string
	FailureLimit    int
	FailureWindow   time.Duration
}

type TOTPIdentityMetadata struct {
	CertificateID  int64
	TFAName        string
	Issuer         string
	Status         string
	CreatedAt      time.Time
	ResetAt        *time.Time
	LastVerifiedAt *time.Time
}

type TOTPSecretResult struct {
	TOTPIdentityMetadata
	Base32Secret string
}

type TOTPResetResult struct {
	TOTPSecretResult
	OperationID int64
	Recovered   bool
}

type totpIdentityState struct {
	TOTPIdentityMetadata
	CommonName        string
	CertificateStatus string
	ArchivedAt        *time.Time
}

type totpResetOperation struct {
	ID             int64
	CertificateID  int64
	IdempotencyKey string
	RequestID      string
	Status         string
	ErrorSummary   string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	CompletedAt    *time.Time
}

type TOTPQRCodeDelivery func([]byte) error

type TOTPService struct {
	db                 *sql.DB
	oathSecretsPath    string
	fileLockPath       string
	qrCodeDirectory    string
	issuer             string
	failureLimit       int
	failureWindow      time.Duration
	now                func() time.Time
	random             io.Reader
	qrGenerator        totpQRCodeGenerator
	replaceFile        func(string, string) error
	beforeCommit       func() error
	beforeSuccessAudit func() error
	beforeCompensation func() error
	certificateLocks   sync.Map
}

func NewTOTPService(
	db *sql.DB,
	config TOTPServiceConfig,
) (*TOTPService, error) {
	if db == nil {
		return nil, errors.New("TOTP database is nil")
	}
	oathPath, err := validatedAbsolutePath(config.OATHSecretsPath)
	if err != nil {
		return nil, errors.New("TOTP oath.secrets path is invalid")
	}
	qrDirectory, err := validatedAbsolutePath(config.QRCodeDirectory)
	if err != nil {
		return nil, errors.New("TOTP QR code directory is invalid")
	}
	qrBinary, err := validatedAbsolutePath(config.QRCodeBinary)
	if err != nil {
		return nil, errors.New("TOTP QR code binary path is invalid")
	}
	issuer := strings.TrimSpace(config.Issuer)
	if issuer == "" {
		issuer = defaultTOTPResetIssuer
	}
	if !validTOTPText(issuer, 128) {
		return nil, errors.New("TOTP issuer is invalid")
	}
	failureLimit := config.FailureLimit
	if failureLimit == 0 {
		failureLimit = defaultTOTPFailureLimit
	}
	failureWindow := config.FailureWindow
	if failureWindow == 0 {
		failureWindow = defaultTOTPFailureWindow
	}
	if failureLimit < 1 || failureLimit > 100 ||
		failureWindow < time.Second ||
		failureWindow > 24*time.Hour {
		return nil, errors.New("TOTP verification limit configuration is invalid")
	}
	return &TOTPService{
		db:              db,
		oathSecretsPath: oathPath,
		fileLockPath:    oathPath + ".lock",
		qrCodeDirectory: qrDirectory,
		issuer:          issuer,
		failureLimit:    failureLimit,
		failureWindow:   failureWindow,
		now:             func() time.Time { return time.Now().UTC() },
		random:          rand.Reader,
		qrGenerator:     commandTOTPQRCodeGenerator{binary: qrBinary},
		replaceFile:     atomicReplaceFile,
	}, nil
}

func validatedAbsolutePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("path must be absolute")
	}
	cleaned := filepath.Clean(path)
	if cleaned == string(filepath.Separator) || cleaned == "." {
		return "", errors.New("path scope is too broad")
	}
	return cleaned, nil
}

func validTOTPText(value string, maxLength int) bool {
	return value != "" &&
		len(value) <= maxLength &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func CanViewTOTPSecret(actor CertificateLifecycleActor) bool {
	return actor.UserID > 0 && actor.IsAdmin
}

func CanViewTOTPQRCode(actor CertificateLifecycleActor) bool {
	return actor.UserID > 0 && actor.IsAdmin
}

func CanVerifyTOTP(actor CertificateLifecycleActor) bool {
	return actor.UserID > 0 && actor.IsAdmin
}

func CanResetTOTP(actor CertificateLifecycleActor) bool {
	return actor.UserID > 0 && actor.IsAdmin
}

func (s *TOTPService) ListIdentityMetadata(
	ctx context.Context,
) (map[int64]TOTPIdentityMetadata, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT
		certificate_id, tfa_name, issuer, status,
		created_at, reset_at, last_verified_at
	FROM totp_identities
	ORDER BY certificate_id`)
	if err != nil {
		return nil, fmt.Errorf("list TOTP identity metadata: %w", err)
	}
	defer rows.Close()

	result := make(map[int64]TOTPIdentityMetadata)
	for rows.Next() {
		metadata, err := scanTOTPIdentityMetadata(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan TOTP identity metadata: %w", err)
		}
		result[metadata.CertificateID] = metadata
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate TOTP identity metadata: %w", err)
	}
	return result, nil
}

func (s *TOTPService) ViewSecret(
	ctx context.Context,
	certificateID int64,
	confirmation string,
	actor CertificateLifecycleActor,
) (TOTPSecretResult, error) {
	var result TOTPSecretResult
	if !CanViewTOTPSecret(actor) {
		_ = s.recordAudit(
			ctx, s.db, actor, TOTPAuditActionSecretView,
			certificateID, "failed", "permission_denied", 0,
		)
		return result, ErrTOTPForbidden
	}
	if certificateID <= 0 {
		s.auditFailure(ctx, actor, TOTPAuditActionSecretView, 0, "invalid_target", 0)
		return result, ErrTOTPNotFound
	}
	lock := s.certificateLock(certificateID)
	lock.Lock()
	defer lock.Unlock()

	fileLock, err := acquireTOTPFileLock(ctx, s.fileLockPath)
	if err != nil {
		s.auditFailure(ctx, actor, TOTPAuditActionSecretView, certificateID, "file_lock_failed", 0)
		return result, ErrTOTPSecretUnavailable
	}
	defer fileLock.release()

	state, err := s.loadUsableIdentity(ctx, certificateID)
	if err != nil {
		s.auditFailure(ctx, actor, TOTPAuditActionSecretView, certificateID, "identity_unavailable", 0)
		return result, err
	}
	if !constantTimeStringEqual(confirmation, state.CommonName) {
		s.auditFailure(ctx, actor, TOTPAuditActionSecretView, certificateID, "confirmation_mismatch", 0)
		return result, ErrTOTPConfirmation
	}
	base32Secret, err := s.readBase32SecretLocked(state.TFAName)
	if err != nil {
		s.auditFailure(ctx, actor, TOTPAuditActionSecretView, certificateID, "secret_read_failed", 0)
		return result, ErrTOTPSecretUnavailable
	}
	if err := s.recordAudit(
		ctx, s.db, actor, TOTPAuditActionSecretView,
		certificateID, "success", "", 0,
	); err != nil {
		return result, ErrTOTPAuditUnavailable
	}
	result = TOTPSecretResult{
		TOTPIdentityMetadata: state.TOTPIdentityMetadata,
		Base32Secret:         base32Secret,
	}
	return result, nil
}

func (s *TOTPService) PerformQRCodeView(
	ctx context.Context,
	certificateID int64,
	confirmation string,
	actor CertificateLifecycleActor,
	deliver TOTPQRCodeDelivery,
) error {
	if !CanViewTOTPQRCode(actor) {
		_ = s.recordAudit(
			ctx, s.db, actor, TOTPAuditActionQRCodeView,
			certificateID, "failed", "permission_denied", 0,
		)
		return ErrTOTPForbidden
	}
	if certificateID <= 0 {
		s.auditFailure(ctx, actor, TOTPAuditActionQRCodeView, 0, "invalid_target", 0)
		return ErrTOTPNotFound
	}
	lock := s.certificateLock(certificateID)
	lock.Lock()
	defer lock.Unlock()

	fileLock, err := acquireTOTPFileLock(ctx, s.fileLockPath)
	if err != nil {
		s.auditFailure(ctx, actor, TOTPAuditActionQRCodeView, certificateID, "file_lock_failed", 0)
		return ErrTOTPQRCodeUnavailable
	}
	defer fileLock.release()

	state, err := s.loadUsableIdentity(ctx, certificateID)
	if err != nil {
		s.auditFailure(ctx, actor, TOTPAuditActionQRCodeView, certificateID, "identity_unavailable", 0)
		return err
	}
	if !constantTimeStringEqual(confirmation, state.CommonName) {
		s.auditFailure(ctx, actor, TOTPAuditActionQRCodeView, certificateID, "confirmation_mismatch", 0)
		return ErrTOTPConfirmation
	}
	imagePath, err := s.qrCodePath(state.CommonName)
	if err != nil {
		s.auditFailure(ctx, actor, TOTPAuditActionQRCodeView, certificateID, "qr_path_invalid", 0)
		return ErrTOTPQRCodeUnavailable
	}
	image, err := readSecureRegularFile(
		imagePath,
		defaultQRCodeMaxSize,
		true,
	)
	if err != nil || len(image) == 0 {
		s.auditFailure(ctx, actor, TOTPAuditActionQRCodeView, certificateID, "qr_read_failed", 0)
		return ErrTOTPQRCodeUnavailable
	}
	if err := s.recordAudit(
		ctx, s.db, actor, TOTPAuditActionQRCodeView,
		certificateID, CertificateAuditResultStarted, "", 0,
	); err != nil {
		return ErrTOTPAuditUnavailable
	}
	if deliver == nil || deliver(image) != nil {
		s.auditFailure(ctx, actor, TOTPAuditActionQRCodeView, certificateID, "qr_delivery_failed", 0)
		return ErrTOTPQRCodeUnavailable
	}
	if err := s.recordAudit(
		ctx, s.db, actor, TOTPAuditActionQRCodeView,
		certificateID, "success", "", 0,
	); err != nil {
		return ErrTOTPAuditUnavailable
	}
	return nil
}

func (s *TOTPService) Verify(
	ctx context.Context,
	certificateID int64,
	code string,
	actor CertificateLifecycleActor,
) error {
	if !CanVerifyTOTP(actor) {
		_ = s.recordAudit(
			ctx, s.db, actor, TOTPAuditActionVerify,
			certificateID, "failed", "permission_denied", 0,
		)
		return ErrTOTPForbidden
	}
	if certificateID <= 0 {
		s.auditFailure(ctx, actor, TOTPAuditActionVerify, 0, "invalid_target", 0)
		return ErrTOTPNotFound
	}
	lock := s.certificateLock(certificateID)
	lock.Lock()
	defer lock.Unlock()

	fileLock, err := acquireTOTPFileLock(ctx, s.fileLockPath)
	if err != nil {
		s.auditFailure(ctx, actor, TOTPAuditActionVerify, certificateID, "file_lock_failed", 0)
		return ErrTOTPSecretUnavailable
	}
	defer fileLock.release()

	state, err := s.loadUsableIdentity(ctx, certificateID)
	if err != nil {
		s.auditFailure(ctx, actor, TOTPAuditActionVerify, certificateID, "identity_unavailable", 0)
		return err
	}
	seed, err := s.readSeedLocked(state.TFAName)
	if err != nil {
		s.auditFailure(ctx, actor, TOTPAuditActionVerify, certificateID, "secret_read_failed", 0)
		return ErrTOTPSecretUnavailable
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrTOTPAuditUnavailable
	}
	defer tx.Rollback()

	failures, err := s.recentVerificationFailures(
		ctx,
		tx,
		actor,
		certificateID,
	)
	if err != nil {
		return ErrTOTPAuditUnavailable
	}
	if failures >= s.failureLimit {
		if err := s.recordAudit(
			ctx, tx, actor, TOTPAuditActionVerify,
			certificateID, "failed", "rate_limited", 0,
		); err != nil {
			return ErrTOTPAuditUnavailable
		}
		if err := tx.Commit(); err != nil {
			return ErrTOTPAuditUnavailable
		}
		return ErrTOTPRateLimited
	}
	if !totpCodePattern.MatchString(code) {
		if err := s.recordAudit(
			ctx, tx, actor, TOTPAuditActionVerify,
			certificateID, "failed", "verification_format", 0,
		); err != nil {
			return ErrTOTPAuditUnavailable
		}
		if err := tx.Commit(); err != nil {
			return ErrTOTPAuditUnavailable
		}
		return ErrTOTPCodeFormat
	}
	expected, err := generateTOTPCode(seed, s.now().UTC())
	if err != nil {
		return ErrTOTPSecretUnavailable
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) != 1 {
		if err := s.recordAudit(
			ctx, tx, actor, TOTPAuditActionVerify,
			certificateID, "failed", "verification_failed", 0,
		); err != nil {
			return ErrTOTPAuditUnavailable
		}
		if err := tx.Commit(); err != nil {
			return ErrTOTPAuditUnavailable
		}
		return ErrTOTPCodeInvalid
	}

	verifiedAt := s.now().UTC()
	updateResult, err := tx.ExecContext(
		ctx,
		`UPDATE totp_identities
		SET last_verified_at = ?
		WHERE certificate_id = ? AND status = 'active'`,
		verifiedAt,
		certificateID,
	)
	if err != nil {
		return ErrTOTPAuditUnavailable
	}
	rowsAffected, err := updateResult.RowsAffected()
	if err != nil || rowsAffected != 1 {
		return ErrTOTPInvalidState
	}
	if err := s.recordAudit(
		ctx, tx, actor, TOTPAuditActionVerify,
		certificateID, "success", "", 0,
	); err != nil {
		return ErrTOTPAuditUnavailable
	}
	if err := tx.Commit(); err != nil {
		return ErrTOTPAuditUnavailable
	}
	return nil
}

func (s *TOTPService) Reset(
	ctx context.Context,
	certificateID int64,
	confirmation string,
	idempotencyKey string,
	actor CertificateLifecycleActor,
) (TOTPResetResult, error) {
	var result TOTPResetResult
	if !CanResetTOTP(actor) {
		_ = s.recordAudit(
			ctx, s.db, actor, TOTPAuditActionReset,
			certificateID, "failed", "permission_denied", 0,
		)
		return result, ErrTOTPForbidden
	}
	if certificateID <= 0 {
		s.auditFailure(ctx, actor, TOTPAuditActionReset, 0, "invalid_target", 0)
		return result, ErrTOTPNotFound
	}
	if !totpIdempotencyPattern.MatchString(idempotencyKey) {
		s.auditFailure(ctx, actor, TOTPAuditActionReset, certificateID, "idempotency_invalid", 0)
		return result, ErrTOTPInvalidInput
	}
	lock := s.certificateLock(certificateID)
	if !lock.TryLock() {
		s.auditFailure(ctx, actor, TOTPAuditActionReset, certificateID, "reset_conflict", 0)
		return result, ErrTOTPResetConflict
	}
	defer lock.Unlock()

	lockContext, cancelLock := context.WithTimeout(ctx, time.Millisecond)
	certificateFileLock, err := acquireTOTPFileLock(
		lockContext,
		s.fileLockPath+".certificate-"+strconv.FormatInt(certificateID, 10),
	)
	cancelLock()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			s.auditFailure(ctx, actor, TOTPAuditActionReset, certificateID, "reset_conflict", 0)
			return result, ErrTOTPResetConflict
		}
		s.auditFailure(ctx, actor, TOTPAuditActionReset, certificateID, "file_lock_failed", 0)
		return result, ErrTOTPSecretUnavailable
	}
	defer certificateFileLock.release()

	fileLock, err := acquireTOTPFileLock(ctx, s.fileLockPath)
	if err != nil {
		s.auditFailure(ctx, actor, TOTPAuditActionReset, certificateID, "file_lock_failed", 0)
		return result, ErrTOTPSecretUnavailable
	}
	defer fileLock.release()

	state, err := s.loadUsableIdentity(ctx, certificateID)
	if err != nil {
		s.auditFailure(ctx, actor, TOTPAuditActionReset, certificateID, "identity_unavailable", 0)
		return result, err
	}
	if !constantTimeStringEqual(confirmation, state.CommonName) {
		s.auditFailure(ctx, actor, TOTPAuditActionReset, certificateID, "confirmation_mismatch", 0)
		return result, ErrTOTPConfirmation
	}

	operation, err := s.prepareResetOperation(
		ctx,
		state,
		idempotencyKey,
		actor,
	)
	if err != nil {
		return result, err
	}
	result.OperationID = operation.ID
	if operation.Status == totpResetStatusCompleted {
		base32Secret, readErr := s.readBase32SecretLocked(state.TFAName)
		if readErr != nil {
			s.auditFailure(ctx, actor, TOTPAuditActionReset, certificateID, "idempotent_read_failed", operation.ID)
			return result, ErrTOTPSecretUnavailable
		}
		currentState, loadErr := s.loadUsableIdentity(ctx, certificateID)
		if loadErr != nil {
			return result, loadErr
		}
		if err := s.recordAudit(
			ctx, s.db, actor, TOTPAuditActionReset,
			certificateID, "success", "", operation.ID,
		); err != nil {
			return result, ErrTOTPAuditUnavailable
		}
		_ = s.cleanupResetBackup(operation.ID)
		result.TOTPSecretResult = TOTPSecretResult{
			TOTPIdentityMetadata: currentState.TOTPIdentityMetadata,
			Base32Secret:         base32Secret,
		}
		result.Recovered = true
		return result, nil
	}

	backupExists, err := s.resetBackupExists(operation.ID)
	if err != nil {
		s.markCompensationRequired(ctx, operation, actor, "backup_invalid")
		return result, ErrTOTPCompensationRequired
	}
	if backupExists {
		if err := s.restoreResetBackup(operation.ID, state.CommonName); err != nil {
			s.markCompensationRequired(ctx, operation, actor, "recovery_failed")
			return result, ErrTOTPCompensationRequired
		}
		if err := s.cleanupResetBackup(operation.ID); err != nil {
			s.markCompensationRequired(ctx, operation, actor, "backup_cleanup_failed")
			return result, ErrTOTPCompensationRequired
		}
		result.Recovered = true
	}

	originalOATH, identities, err := s.readOATHSecretsLocked()
	if err != nil {
		s.failResetOperation(ctx, operation, actor, "secret_read_failed")
		return result, ErrTOTPSecretUnavailable
	}
	if _, err := findOATHIdentity(identities, state.TFAName); err != nil {
		s.failResetOperation(ctx, operation, actor, "identity_mismatch")
		return result, ErrTOTPSecretUnavailable
	}

	newSeed := make([]byte, totpSecretByteLength)
	if _, err := io.ReadFull(s.random, newSeed); err != nil {
		s.failResetOperation(ctx, operation, actor, "random_generation_failed")
		return result, ErrTOTPSecretUnavailable
	}
	hexSeed := strings.ToUpper(hex.EncodeToString(newSeed))
	base32Secret, err := HexSeedToBase32(hexSeed)
	if err != nil {
		s.failResetOperation(ctx, operation, actor, "secret_generation_failed")
		return result, ErrTOTPSecretUnavailable
	}
	updatedOATH, err := replaceOATHIdentity(
		identities,
		state.TFAName,
		hexSeed,
	)
	if err != nil {
		s.failResetOperation(ctx, operation, actor, "identity_replace_failed")
		return result, ErrTOTPSecretUnavailable
	}
	qrPayload := buildOTPAuthURI(s.issuer, state.TFAName, base32Secret)
	qrTemporaryPath, err := s.generateTemporaryQRCode(ctx, qrPayload)
	qrPayload = ""
	if err != nil {
		s.failResetOperation(ctx, operation, actor, "qr_generation_failed")
		return result, ErrTOTPQRCodeUnavailable
	}
	defer os.Remove(qrTemporaryPath)

	oathTemporaryFile, err := createSecureTemporaryFile(
		filepath.Dir(s.oathSecretsPath),
		".oath-secrets-reset-*.tmp",
	)
	if err != nil {
		s.failResetOperation(ctx, operation, actor, "temporary_write_failed")
		return result, ErrTOTPSecretUnavailable
	}
	oathTemporaryPath := oathTemporaryFile.Name()
	defer os.Remove(oathTemporaryPath)
	if err := writeAndSync(oathTemporaryFile, updatedOATH); err != nil {
		s.failResetOperation(ctx, operation, actor, "temporary_write_failed")
		return result, ErrTOTPSecretUnavailable
	}
	if err := s.createResetBackup(
		operation.ID,
		state.CommonName,
		originalOATH,
	); err != nil {
		s.failResetOperation(ctx, operation, actor, "backup_create_failed")
		return result, ErrTOTPSecretUnavailable
	}

	qrPath, _ := s.qrCodePath(state.CommonName)
	if err := s.replaceFile(oathTemporaryPath, s.oathSecretsPath); err != nil {
		return result, s.compensateResetFailure(
			ctx, operation, actor, state.CommonName, "oath_replace_failed",
		)
	}
	if err := s.replaceFile(qrTemporaryPath, qrPath); err != nil {
		return result, s.compensateResetFailure(
			ctx, operation, actor, state.CommonName, "qr_replace_failed",
		)
	}

	resetAt := s.now().UTC()
	if err := s.completeResetOperation(
		ctx,
		operation,
		actor,
		resetAt,
	); err != nil {
		return result, s.compensateResetFailure(
			ctx, operation, actor, state.CommonName, "database_commit_failed",
		)
	}
	_ = s.cleanupResetBackup(operation.ID)

	state.TOTPIdentityMetadata.Issuer = s.issuer
	state.TOTPIdentityMetadata.Status = "active"
	state.TOTPIdentityMetadata.ResetAt = &resetAt
	state.TOTPIdentityMetadata.LastVerifiedAt = nil
	result.TOTPSecretResult = TOTPSecretResult{
		TOTPIdentityMetadata: state.TOTPIdentityMetadata,
		Base32Secret:         base32Secret,
	}
	return result, nil
}

func (s *TOTPService) RecordOperationAudit(
	ctx context.Context,
	actor CertificateLifecycleActor,
	action string,
	certificateID int64,
	errorSummary string,
) error {
	if err := s.recordAudit(
		ctx,
		s.db,
		actor,
		action,
		certificateID,
		"failed",
		errorSummary,
		0,
	); err != nil {
		return ErrTOTPAuditUnavailable
	}
	return nil
}

func (s *TOTPService) certificateLock(certificateID int64) *sync.Mutex {
	value, _ := s.certificateLocks.LoadOrStore(certificateID, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func (s *TOTPService) loadUsableIdentity(
	ctx context.Context,
	certificateID int64,
) (totpIdentityState, error) {
	if certificateID <= 0 {
		return totpIdentityState{}, ErrTOTPNotFound
	}
	row := s.db.QueryRowContext(ctx, `SELECT
		c.id, c.common_name, c.status, c.archived_at,
		t.certificate_id, t.tfa_name, t.issuer, t.status,
		t.created_at, t.reset_at, t.last_verified_at
	FROM certificates AS c
	JOIN totp_identities AS t ON t.certificate_id = c.id
	WHERE c.id = ?`, certificateID)
	var state totpIdentityState
	var archivedAt, resetAt, lastVerifiedAt sql.NullTime
	if err := row.Scan(
		&state.CertificateID,
		&state.CommonName,
		&state.CertificateStatus,
		&archivedAt,
		&state.TOTPIdentityMetadata.CertificateID,
		&state.TFAName,
		&state.Issuer,
		&state.Status,
		&state.CreatedAt,
		&resetAt,
		&lastVerifiedAt,
	); errors.Is(err, sql.ErrNoRows) {
		return totpIdentityState{}, ErrTOTPNotFound
	} else if err != nil {
		return totpIdentityState{}, ErrTOTPNotFound
	}
	if archivedAt.Valid {
		value := archivedAt.Time.UTC()
		state.ArchivedAt = &value
	}
	if resetAt.Valid {
		value := resetAt.Time.UTC()
		state.ResetAt = &value
	}
	if lastVerifiedAt.Valid {
		value := lastVerifiedAt.Time.UTC()
		state.LastVerifiedAt = &value
	}
	if !ValidateCertificateCommonName(state.CommonName) ||
		!tfaNamePattern.MatchString(state.TFAName) ||
		!validTOTPText(state.Issuer, 128) ||
		state.Status != "active" ||
		state.ArchivedAt != nil ||
		(state.CertificateStatus != "valid" &&
			state.CertificateStatus != "expired") {
		return totpIdentityState{}, ErrTOTPInvalidState
	}
	return state, nil
}

func scanTOTPIdentityMetadata(
	scan rowScanner,
) (TOTPIdentityMetadata, error) {
	var metadata TOTPIdentityMetadata
	var resetAt, lastVerifiedAt sql.NullTime
	if err := scan(
		&metadata.CertificateID,
		&metadata.TFAName,
		&metadata.Issuer,
		&metadata.Status,
		&metadata.CreatedAt,
		&resetAt,
		&lastVerifiedAt,
	); err != nil {
		return TOTPIdentityMetadata{}, err
	}
	if resetAt.Valid {
		value := resetAt.Time.UTC()
		metadata.ResetAt = &value
	}
	if lastVerifiedAt.Valid {
		value := lastVerifiedAt.Time.UTC()
		metadata.LastVerifiedAt = &value
	}
	return metadata, nil
}

func (s *TOTPService) readOATHSecretsLocked() ([]byte, []oathIdentity, error) {
	data, err := readSecureRegularFile(
		s.oathSecretsPath,
		defaultOATHSecretsMaxSize,
		true,
	)
	if err != nil {
		return nil, nil, err
	}
	identities, err := parseOATHSecrets(data)
	if err != nil {
		return nil, nil, err
	}
	return data, identities, nil
}

func (s *TOTPService) readSeedLocked(tfaName string) ([]byte, error) {
	_, identities, err := s.readOATHSecretsLocked()
	if err != nil {
		return nil, err
	}
	identity, err := findOATHIdentity(identities, tfaName)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(identity.HexSeed)
	if err != nil || len(seed) == 0 {
		return nil, errors.New("TOTP seed format is invalid")
	}
	return seed, nil
}

func (s *TOTPService) readBase32SecretLocked(tfaName string) (string, error) {
	_, identities, err := s.readOATHSecretsLocked()
	if err != nil {
		return "", err
	}
	identity, err := findOATHIdentity(identities, tfaName)
	if err != nil {
		return "", err
	}
	return HexSeedToBase32(identity.HexSeed)
}

func (s *TOTPService) qrCodePath(commonName string) (string, error) {
	if !ValidateCertificateCommonName(commonName) {
		return "", errors.New("certificate identity is invalid")
	}
	path := filepath.Join(s.qrCodeDirectory, commonName+".png")
	if filepath.Dir(path) != s.qrCodeDirectory {
		return "", errors.New("TOTP QR code path is invalid")
	}
	return path, nil
}

func (s *TOTPService) recentVerificationFailures(
	ctx context.Context,
	tx *sql.Tx,
	actor CertificateLifecycleActor,
	certificateID int64,
) (int, error) {
	var count int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*)
	FROM audit_logs AS failure
	WHERE failure.action = ?
		AND failure.target_type = 'certificate'
		AND failure.target_id = ?
		AND failure.actor_user_id = ?
		AND failure.source_ip = ?
		AND failure.result = 'failed'
		AND failure.error_summary IN (
			'verification_failed',
			'verification_format'
		)
		AND failure.created_at >= ?
		AND NOT EXISTS (
			SELECT 1 FROM audit_logs AS success
			WHERE success.action = failure.action
				AND success.target_type = failure.target_type
				AND success.target_id = failure.target_id
				AND success.actor_user_id = failure.actor_user_id
				AND success.source_ip = failure.source_ip
				AND success.result = 'success'
				AND success.created_at > failure.created_at
		)`,
		TOTPAuditActionVerify,
		strconv.FormatInt(certificateID, 10),
		actor.UserID,
		normalizeAuditSourceIP(actor.SourceIP),
		s.now().UTC().Add(-s.failureWindow),
	).Scan(&count)
	return count, err
}

func (s *TOTPService) prepareResetOperation(
	ctx context.Context,
	state totpIdentityState,
	idempotencyKey string,
	actor CertificateLifecycleActor,
) (totpResetOperation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return totpResetOperation{}, ErrTOTPAuditUnavailable
	}
	defer tx.Rollback()

	var unresolved int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*)
		FROM totp_reset_operations
		WHERE certificate_id = ?
			AND status = 'compensation_required'`,
		state.CertificateID,
	).Scan(&unresolved); err != nil {
		return totpResetOperation{}, ErrTOTPAuditUnavailable
	}
	if unresolved > 0 {
		return totpResetOperation{}, ErrTOTPCompensationRequired
	}

	operation, found, err := loadResetOperation(
		ctx,
		tx,
		state.CertificateID,
		idempotencyKey,
	)
	if err != nil {
		return totpResetOperation{}, ErrTOTPAuditUnavailable
	}
	if found && operation.Status == totpResetStatusCompleted {
		if err := tx.Commit(); err != nil {
			return totpResetOperation{}, ErrTOTPAuditUnavailable
		}
		return operation, nil
	}
	if found && operation.Status == totpResetStatusCompensationRequired {
		return totpResetOperation{}, ErrTOTPCompensationRequired
	}

	var otherPrepared int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*)
		FROM totp_reset_operations
		WHERE certificate_id = ?
			AND status = 'prepared'
			AND idempotency_key <> ?`,
		state.CertificateID,
		idempotencyKey,
	).Scan(&otherPrepared); err != nil {
		return totpResetOperation{}, ErrTOTPAuditUnavailable
	}
	if otherPrepared > 0 {
		return totpResetOperation{}, ErrTOTPResetConflict
	}

	now := s.now().UTC()
	if found {
		if _, err := tx.ExecContext(ctx, `UPDATE totp_reset_operations
			SET request_id = ?, status = 'prepared',
				error_summary = '', updated_at = ?, completed_at = NULL
			WHERE id = ?`,
			normalizedRequestID(actor.RequestID),
			now,
			operation.ID,
		); err != nil {
			return totpResetOperation{}, ErrTOTPAuditUnavailable
		}
		operation.RequestID = normalizedRequestID(actor.RequestID)
		operation.Status = totpResetStatusPrepared
		operation.ErrorSummary = ""
		operation.UpdatedAt = now
		operation.CompletedAt = nil
	} else {
		insertResult, err := tx.ExecContext(ctx, `INSERT INTO totp_reset_operations (
			certificate_id, idempotency_key, request_id, status,
			error_summary, created_at, updated_at
		) VALUES (?, ?, ?, 'prepared', '', ?, ?)`,
			state.CertificateID,
			idempotencyKey,
			normalizedRequestID(actor.RequestID),
			now,
			now,
		)
		if err != nil {
			return totpResetOperation{}, ErrTOTPResetConflict
		}
		operation.ID, err = insertResult.LastInsertId()
		if err != nil {
			return totpResetOperation{}, ErrTOTPAuditUnavailable
		}
		operation.CertificateID = state.CertificateID
		operation.IdempotencyKey = idempotencyKey
		operation.RequestID = normalizedRequestID(actor.RequestID)
		operation.Status = totpResetStatusPrepared
		operation.CreatedAt = now
		operation.UpdatedAt = now
	}
	if err := s.recordAudit(
		ctx, tx, actor, TOTPAuditActionReset,
		state.CertificateID, CertificateAuditResultStarted, "", operation.ID,
	); err != nil {
		return totpResetOperation{}, ErrTOTPAuditUnavailable
	}
	if err := tx.Commit(); err != nil {
		return totpResetOperation{}, ErrTOTPAuditUnavailable
	}
	return operation, nil
}

type resetOperationQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadResetOperation(
	ctx context.Context,
	queryer resetOperationQueryer,
	certificateID int64,
	idempotencyKey string,
) (totpResetOperation, bool, error) {
	var operation totpResetOperation
	var completedAt sql.NullTime
	err := queryer.QueryRowContext(ctx, `SELECT
		id, certificate_id, idempotency_key, request_id, status,
		error_summary, created_at, updated_at, completed_at
	FROM totp_reset_operations
	WHERE certificate_id = ? AND idempotency_key = ?`,
		certificateID,
		idempotencyKey,
	).Scan(
		&operation.ID,
		&operation.CertificateID,
		&operation.IdempotencyKey,
		&operation.RequestID,
		&operation.Status,
		&operation.ErrorSummary,
		&operation.CreatedAt,
		&operation.UpdatedAt,
		&completedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return totpResetOperation{}, false, nil
	}
	if err != nil {
		return totpResetOperation{}, false, err
	}
	if completedAt.Valid {
		value := completedAt.Time.UTC()
		operation.CompletedAt = &value
	}
	return operation, true, nil
}

func (s *TOTPService) generateTemporaryQRCode(
	ctx context.Context,
	payload string,
) (string, error) {
	file, err := createSecureTemporaryFile(
		s.qrCodeDirectory,
		".totp-qr-reset-*.tmp",
	)
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err := s.qrGenerator.Generate(ctx, payload, file); err != nil {
		file.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	data, err := readSecureRegularFile(path, defaultQRCodeMaxSize, true)
	if err != nil || len(data) == 0 {
		_ = os.Remove(path)
		return "", errors.New("generated TOTP QR code is invalid")
	}
	return path, nil
}

func buildOTPAuthURI(issuer string, tfaName string, base32Secret string) string {
	query := url.Values{}
	query.Set("issuer", issuer)
	query.Set("secret", base32Secret)
	label := url.PathEscape(issuer + ":" + tfaName)
	return "otpauth://totp/" + label + "?" + query.Encode()
}

func (s *TOTPService) resetBackupDirectory(operationID int64) string {
	return filepath.Join(
		s.qrCodeDirectory,
		".totp-reset-"+strconv.FormatInt(operationID, 10),
	)
}

func (s *TOTPService) resetBackupExists(operationID int64) (bool, error) {
	path := s.resetBackupDirectory(operationID)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() ||
		info.Mode().Perm()&0o077 != 0 {
		return false, errors.New("TOTP reset backup directory is invalid")
	}
	return true, nil
}

func (s *TOTPService) createResetBackup(
	operationID int64,
	commonName string,
	oathData []byte,
) (err error) {
	directory := s.resetBackupDirectory(operationID)
	if err := os.Mkdir(directory, 0o700); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = s.cleanupResetBackup(operationID)
		}
	}()
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	if err := writeExclusiveSecureFile(
		filepath.Join(directory, "oath.secrets.backup"),
		oathData,
	); err != nil {
		return err
	}
	qrPath, err := s.qrCodePath(commonName)
	if err != nil {
		return err
	}
	qrData, err := readSecureRegularFile(
		qrPath,
		defaultQRCodeMaxSize,
		true,
	)
	switch {
	case err == nil:
		err = writeExclusiveSecureFile(
			filepath.Join(directory, "qr.backup"),
			qrData,
		)
		complete = err == nil
		return err
	case errors.Is(err, os.ErrNotExist):
		err = writeExclusiveSecureFile(
			filepath.Join(directory, "qr.missing"),
			[]byte("missing\n"),
		)
		complete = err == nil
		return err
	default:
		return err
	}
}

func writeExclusiveSecureFile(path string, data []byte) error {
	file, err := os.OpenFile(
		path,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	return writeAndSync(file, data)
}

func (s *TOTPService) restoreResetBackup(
	operationID int64,
	commonName string,
) error {
	if s.beforeCompensation != nil {
		if err := s.beforeCompensation(); err != nil {
			return err
		}
	}
	directory := s.resetBackupDirectory(operationID)
	oathData, err := readSecureRegularFile(
		filepath.Join(directory, "oath.secrets.backup"),
		defaultOATHSecretsMaxSize,
		true,
	)
	if err != nil {
		return err
	}
	if _, err := parseOATHSecrets(oathData); err != nil {
		return err
	}
	if err := writeAtomicSecureFile(s.oathSecretsPath, oathData); err != nil {
		return err
	}
	qrPath, err := s.qrCodePath(commonName)
	if err != nil {
		return err
	}
	qrBackupPath := filepath.Join(directory, "qr.backup")
	qrData, qrErr := readSecureRegularFile(
		qrBackupPath,
		defaultQRCodeMaxSize,
		true,
	)
	if qrErr == nil {
		if len(qrData) == 0 {
			return errors.New("TOTP QR code backup is invalid")
		}
		return writeAtomicSecureFile(qrPath, qrData)
	}
	if !errors.Is(qrErr, os.ErrNotExist) {
		return qrErr
	}
	if _, markerErr := readSecureRegularFile(
		filepath.Join(directory, "qr.missing"),
		64,
		true,
	); markerErr != nil {
		return markerErr
	}
	if err := os.Remove(qrPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(s.qrCodeDirectory)
}

func writeAtomicSecureFile(path string, data []byte) error {
	file, err := createSecureTemporaryFile(
		filepath.Dir(path),
		".totp-restore-*.tmp",
	)
	if err != nil {
		return err
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := writeAndSync(file, data); err != nil {
		return err
	}
	return atomicReplaceFile(temporaryPath, path)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s *TOTPService) cleanupResetBackup(operationID int64) error {
	directory := s.resetBackupDirectory(operationID)
	for _, name := range []string{
		"oath.secrets.backup",
		"qr.backup",
		"qr.missing",
	} {
		if err := os.Remove(filepath.Join(directory, name)); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Remove(directory); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(s.qrCodeDirectory)
}

func (s *TOTPService) completeResetOperation(
	ctx context.Context,
	operation totpResetOperation,
	actor CertificateLifecycleActor,
	resetAt time.Time,
) error {
	if s.beforeCommit != nil {
		if err := s.beforeCommit(); err != nil {
			return err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE totp_identities
		SET issuer = ?, status = 'active',
			reset_at = ?, last_verified_at = NULL
		WHERE certificate_id = ? AND status = 'active'`,
		s.issuer,
		resetAt,
		operation.CertificateID,
	)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected != 1 {
		return ErrTOTPInvalidState
	}
	result, err = tx.ExecContext(ctx, `UPDATE totp_reset_operations
		SET request_id = ?, status = 'completed',
			error_summary = '', updated_at = ?, completed_at = ?
		WHERE id = ? AND status = 'prepared'`,
		normalizedRequestID(actor.RequestID),
		resetAt,
		resetAt,
		operation.ID,
	)
	if err != nil {
		return err
	}
	rowsAffected, err = result.RowsAffected()
	if err != nil || rowsAffected != 1 {
		return ErrTOTPResetConflict
	}
	if s.beforeSuccessAudit != nil {
		if err := s.beforeSuccessAudit(); err != nil {
			return err
		}
	}
	if err := s.recordAudit(
		ctx, tx, actor, TOTPAuditActionReset,
		operation.CertificateID, "success", "", operation.ID,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *TOTPService) failResetOperation(
	ctx context.Context,
	operation totpResetOperation,
	actor CertificateLifecycleActor,
	errorSummary string,
) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	now := s.now().UTC()
	if _, err := tx.ExecContext(ctx, `UPDATE totp_reset_operations
		SET request_id = ?, status = 'failed',
			error_summary = ?, updated_at = ?, completed_at = NULL
		WHERE id = ? AND status = 'prepared'`,
		normalizedRequestID(actor.RequestID),
		errorSummary,
		now,
		operation.ID,
	); err != nil {
		return
	}
	if err := s.recordAudit(
		ctx, tx, actor, TOTPAuditActionReset,
		operation.CertificateID, "failed", errorSummary, operation.ID,
	); err != nil {
		return
	}
	_ = tx.Commit()
}

func (s *TOTPService) compensateResetFailure(
	ctx context.Context,
	operation totpResetOperation,
	actor CertificateLifecycleActor,
	commonName string,
	errorSummary string,
) error {
	if err := s.restoreResetBackup(operation.ID, commonName); err != nil {
		s.markCompensationRequired(
			ctx,
			operation,
			actor,
			"compensation_required",
		)
		return ErrTOTPCompensationRequired
	}
	_ = s.cleanupResetBackup(operation.ID)
	s.failResetOperation(ctx, operation, actor, errorSummary)
	return ErrTOTPSecretUnavailable
}

func (s *TOTPService) markCompensationRequired(
	ctx context.Context,
	operation totpResetOperation,
	actor CertificateLifecycleActor,
	errorSummary string,
) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	now := s.now().UTC()
	if _, err := tx.ExecContext(ctx, `UPDATE totp_reset_operations
		SET request_id = ?, status = 'compensation_required',
			error_summary = ?, updated_at = ?, completed_at = NULL
		WHERE id = ?`,
		normalizedRequestID(actor.RequestID),
		errorSummary,
		now,
		operation.ID,
	); err != nil {
		return
	}
	if err := s.recordAudit(
		ctx, tx, actor, TOTPAuditActionReset,
		operation.CertificateID, "failed", errorSummary, operation.ID,
	); err != nil {
		return
	}
	_ = tx.Commit()
}

func (s *TOTPService) auditFailure(
	ctx context.Context,
	actor CertificateLifecycleActor,
	action string,
	certificateID int64,
	errorSummary string,
	operationID int64,
) {
	_ = s.recordAudit(
		ctx,
		s.db,
		actor,
		action,
		certificateID,
		"failed",
		errorSummary,
		operationID,
	)
}

func (s *TOTPService) recordAudit(
	ctx context.Context,
	executor auditExecutor,
	actor CertificateLifecycleActor,
	action string,
	certificateID int64,
	result string,
	errorSummary string,
	operationID int64,
) error {
	summary, validAction := map[string]string{
		TOTPAuditActionQRCodeView: "TOTP QR code view",
		TOTPAuditActionSecretView: "TOTP secret view",
		TOTPAuditActionVerify:     "TOTP verification",
		TOTPAuditActionReset:      "TOTP reset",
	}[action]
	if !validAction {
		return errors.New("invalid TOTP audit action")
	}
	switch result {
	case CertificateAuditResultStarted, "success", "failed":
	default:
		return errors.New("invalid TOTP audit result")
	}
	if errorSummary != "" &&
		!auditErrorSummaryPattern.MatchString(errorSummary) {
		return errors.New("invalid TOTP audit error summary")
	}
	if operationID > 0 {
		summary += " operation_id=" + strconv.FormatInt(operationID, 10)
	}
	targetID := ""
	if certificateID > 0 {
		targetID = strconv.FormatInt(certificateID, 10)
	}
	_, err := executor.ExecContext(ctx, `INSERT INTO audit_logs (
		actor_user_id, source_ip, action, target_type, target_id,
		summary, result, error_summary, request_id, created_at
	) VALUES (?, ?, ?, 'certificate', ?, ?, ?, ?, ?, ?)`,
		nullableActorUserID(actor.UserID),
		normalizeAuditSourceIP(actor.SourceIP),
		action,
		targetID,
		summary,
		result,
		errorSummary,
		normalizedRequestID(actor.RequestID),
		s.now().UTC(),
	)
	return err
}

func normalizedRequestID(requestID string) string {
	if auditRequestIDPattern.MatchString(requestID) {
		return requestID
	}
	return "unavailable"
}
