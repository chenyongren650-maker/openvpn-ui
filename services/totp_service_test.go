package services

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/d3vilh/openvpn-ui/migrations"
)

const (
	syntheticTOTPSeedHex        = "3132333435363738393031323334353637383930"
	syntheticTOTPReplacementHex = "00112233445566778899AABBCCDDEEFF00112233"
)

var totpTestNow = time.Date(2026, time.July, 27, 8, 0, 0, 0, time.UTC)

type fakeTOTPQRCodeGenerator struct {
	mu      sync.Mutex
	fail    bool
	started chan struct{}
	release chan struct{}
}

type failingTOTPReader struct{}

func (failingTOTPReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic random source failure")
}

func (g *fakeTOTPQRCodeGenerator) Generate(
	_ context.Context,
	_ string,
	output *os.File,
) error {
	g.mu.Lock()
	fail := g.fail
	started := g.started
	release := g.release
	g.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if release != nil {
		<-release
	}
	if fail {
		return errors.New("synthetic QR generation failure")
	}
	_, err := output.Write([]byte("synthetic-png"))
	return err
}

type totpTestFixture struct {
	service      *TOTPService
	db           *sql.DB
	databasePath string
	clientsDir   string
	oathPath     string
	qrPath       string
	qrGenerator  *fakeTOTPQRCodeGenerator
}

func newTOTPTestFixture(t *testing.T) *totpTestFixture {
	t.Helper()
	root := t.TempDir()
	databasePath := filepath.Join(root, "db", "data.db")
	if _, err := migrations.Up(context.Background(), databasePath); err != nil {
		t.Fatalf("initialize TOTP test database: %v", err)
	}
	dsn := &url.URL{Scheme: "file", Path: databasePath}
	query := dsn.Query()
	query.Set("_busy_timeout", "5000")
	query.Set("_foreign_keys", "on")
	query.Set("_txlock", "immediate")
	dsn.RawQuery = query.Encode()
	db, err := sql.Open("sqlite3", dsn.String())
	if err != nil {
		t.Fatalf("open TOTP test database: %v", err)
	}
	db.SetMaxOpenConns(8)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`INSERT INTO certificates (
			id, common_name, serial_number, fingerprint, status, created_at
		) VALUES (
			1, 'totp-test-client', 'F1', 'synthetic-fingerprint',
			'valid', '2026-07-27T07:00:00Z'
		)`,
		`INSERT INTO totp_identities (
			certificate_id, tfa_name, issuer, status, created_at
		) VALUES (
			1, 'totp-test@example.invalid', 'ZHISUAN', 'active',
			'2026-07-27T07:00:00Z'
		)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("seed TOTP test database: %v", err)
		}
	}

	clientsDir := filepath.Join(root, "clients")
	if err := os.MkdirAll(clientsDir, 0o700); err != nil {
		t.Fatalf("create TOTP test clients directory: %v", err)
	}
	oathPath := filepath.Join(clientsDir, "oath.secrets")
	if err := os.WriteFile(
		oathPath,
		[]byte("totp-test@example.invalid:"+syntheticTOTPSeedHex+"\n"),
		0o600,
	); err != nil {
		t.Fatalf("write synthetic oath.secrets: %v", err)
	}
	qrPath := filepath.Join(clientsDir, "totp-test-client.png")
	if err := os.WriteFile(qrPath, []byte("synthetic-old-png"), 0o600); err != nil {
		t.Fatalf("write synthetic QR code: %v", err)
	}
	service, err := NewTOTPService(db, TOTPServiceConfig{
		OATHSecretsPath: oathPath,
		QRCodeDirectory: clientsDir,
		QRCodeBinary:    "/bin/false",
		Issuer:          "ZHISUAN",
	})
	if err != nil {
		t.Fatalf("create TOTP service: %v", err)
	}
	qrGenerator := &fakeTOTPQRCodeGenerator{}
	service.qrGenerator = qrGenerator
	service.now = func() time.Time { return totpTestNow }
	return &totpTestFixture{
		service:      service,
		db:           db,
		databasePath: databasePath,
		clientsDir:   clientsDir,
		oathPath:     oathPath,
		qrPath:       qrPath,
		qrGenerator:  qrGenerator,
	}
}

func totpAdminActor() CertificateLifecycleActor {
	return CertificateLifecycleActor{
		UserID:    1,
		IsAdmin:   true,
		SourceIP:  "192.0.2.10",
		RequestID: "totp-request-1",
	}
}

func TestHexSeedToBase32Validation(t *testing.T) {
	expected, err := HexSeedToBase32(syntheticTOTPSeedHex)
	if err != nil || expected == "" {
		t.Fatal("public synthetic HEX test vector did not convert")
	}
	lowercase, err := HexSeedToBase32(strings.ToLower(syntheticTOTPSeedHex))
	if err != nil || lowercase != expected {
		t.Fatal("lowercase HEX test vector produced a different Base32 result")
	}
	for _, invalid := range []string{"", "0", "GG", "00 11"} {
		if converted, err := HexSeedToBase32(invalid); err == nil || converted != "" {
			t.Fatal("invalid HEX input was converted")
		}
	}
}

func TestOATHSecretsParserUsesExactCaseSensitiveIdentity(t *testing.T) {
	data := []byte(
		"totp-test@example.invalid:" + syntheticTOTPSeedHex + "\n" +
			"totp-test@example.invalid-extra:" + syntheticTOTPReplacementHex + "\n",
	)
	identities, err := parseOATHSecrets(data)
	if err != nil {
		t.Fatalf("parse synthetic identities: %v", err)
	}
	identity, err := findOATHIdentity(
		identities,
		"totp-test@example.invalid",
	)
	if err != nil || identity.HexSeed != syntheticTOTPSeedHex {
		t.Fatal("exact TFA name did not select the expected synthetic identity")
	}
	if _, err := findOATHIdentity(
		identities,
		"TOTP-TEST@example.invalid",
	); err == nil {
		t.Fatal("case-changed TFA name matched unexpectedly")
	}
	duplicate := []byte(
		"totp-test@example.invalid:" + syntheticTOTPSeedHex + "\n" +
			"totp-test@example.invalid:" + syntheticTOTPReplacementHex + "\n",
	)
	if _, err := parseOATHSecrets(duplicate); err == nil {
		t.Fatal("duplicate exact TFA names were accepted")
	}
	overlongLine := bytes.Repeat([]byte("a"), defaultOATHLineMaxSize+1)
	if _, err := parseOATHSecrets(
		append(overlongLine, '\n'),
	); err == nil {
		t.Fatal("overlong TOTP identity line was accepted")
	}
	if _, err := parseOATHSecrets(
		[]byte("unsafe;name:" + syntheticTOTPSeedHex + "\n"),
	); err == nil {
		t.Fatal("TOTP identity containing command characters was accepted")
	}
}

func TestViewSecretRequiresPermissionConfirmationAndSecureFile(t *testing.T) {
	fixture := newTOTPTestFixture(t)
	nonAdmin := totpAdminActor()
	nonAdmin.UserID = 2
	nonAdmin.IsAdmin = false
	if _, err := fixture.service.ViewSecret(
		context.Background(),
		1,
		"totp-test-client",
		nonAdmin,
	); !errors.Is(err, ErrTOTPForbidden) {
		t.Fatalf("non-admin Secret view error = %v", err)
	}
	if _, err := fixture.service.ViewSecret(
		context.Background(),
		1,
		"wrong-name",
		totpAdminActor(),
	); !errors.Is(err, ErrTOTPConfirmation) {
		t.Fatalf("wrong confirmation Secret view error = %v", err)
	}
	result, err := fixture.service.ViewSecret(
		context.Background(),
		1,
		"totp-test-client",
		totpAdminActor(),
	)
	if err != nil || result.Base32Secret == "" ||
		result.Base32Secret == syntheticTOTPSeedHex {
		t.Fatal("authorized Secret view did not return only Base32 data")
	}
	assertTOTPAuditContainsNoSyntheticSecret(t, fixture.db, result.Base32Secret, "")

	if err := os.Chmod(fixture.oathPath, 0o644); err != nil {
		t.Fatalf("widen synthetic oath.secrets permissions: %v", err)
	}
	if _, err := fixture.service.ViewSecret(
		context.Background(),
		1,
		"totp-test-client",
		totpAdminActor(),
	); !errors.Is(err, ErrTOTPSecretUnavailable) {
		t.Fatalf("broad-permission Secret view error = %v", err)
	}
}

func TestViewSecretRejectsSymlinkDuplicateAndOversizedFiles(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *totpTestFixture)
	}{
		{
			name: "symlink",
			mutate: func(t *testing.T, fixture *totpTestFixture) {
				target := filepath.Join(fixture.clientsDir, "synthetic-target")
				if err := os.WriteFile(
					target,
					[]byte("totp-test@example.invalid:"+syntheticTOTPSeedHex+"\n"),
					0o600,
				); err != nil {
					t.Fatalf("write synthetic target: %v", err)
				}
				if err := os.Remove(fixture.oathPath); err != nil {
					t.Fatalf("remove synthetic oath.secrets: %v", err)
				}
				if err := os.Symlink(target, fixture.oathPath); err != nil {
					t.Fatalf("create synthetic symlink: %v", err)
				}
			},
		},
		{
			name: "duplicate",
			mutate: func(t *testing.T, fixture *totpTestFixture) {
				data := []byte(
					"totp-test@example.invalid:" + syntheticTOTPSeedHex + "\n" +
						"totp-test@example.invalid:" + syntheticTOTPReplacementHex + "\n",
				)
				if err := os.WriteFile(fixture.oathPath, data, 0o600); err != nil {
					t.Fatalf("write duplicate synthetic identities: %v", err)
				}
			},
		},
		{
			name: "oversized",
			mutate: func(t *testing.T, fixture *totpTestFixture) {
				data := bytes.Repeat(
					[]byte("x"),
					defaultOATHSecretsMaxSize+1,
				)
				if err := os.WriteFile(fixture.oathPath, data, 0o600); err != nil {
					t.Fatalf("write oversized synthetic identity file: %v", err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTOTPTestFixture(t)
			test.mutate(t, fixture)
			if _, err := fixture.service.ViewSecret(
				context.Background(),
				1,
				"totp-test-client",
				totpAdminActor(),
			); !errors.Is(err, ErrTOTPSecretUnavailable) {
				t.Fatalf("unsafe Secret view error = %v", err)
			}
		})
	}
}

func TestQRCodeViewRejectsUnsafeFileAndAuditsDelivery(t *testing.T) {
	fixture := newTOTPTestFixture(t)
	delivered := false
	if err := fixture.service.PerformQRCodeView(
		context.Background(),
		1,
		"totp-test-client",
		totpAdminActor(),
		func(data []byte) error {
			delivered = len(data) > 0
			return nil
		},
	); err != nil || !delivered {
		t.Fatalf("deliver synthetic QR code: %v", err)
	}
	var started, succeeded int
	if err := fixture.db.QueryRow(`SELECT
		SUM(CASE WHEN result = 'started' THEN 1 ELSE 0 END),
		SUM(CASE WHEN result = 'success' THEN 1 ELSE 0 END)
		FROM audit_logs WHERE action = ?`,
		TOTPAuditActionQRCodeView,
	).Scan(&started, &succeeded); err != nil ||
		started != 1 || succeeded != 1 {
		t.Fatalf(
			"QR audit started=%d success=%d error=%v",
			started,
			succeeded,
			err,
		)
	}
	if err := os.Chmod(fixture.qrPath, 0o644); err != nil {
		t.Fatalf("widen synthetic QR permissions: %v", err)
	}
	if err := fixture.service.PerformQRCodeView(
		context.Background(),
		1,
		"totp-test-client",
		totpAdminActor(),
		func([]byte) error { return nil },
	); !errors.Is(err, ErrTOTPQRCodeUnavailable) {
		t.Fatalf("broad-permission QR view error = %v", err)
	}
}

func TestTOTPServiceRejectsDatabasePathTraversalIdentity(t *testing.T) {
	fixture := newTOTPTestFixture(t)
	if _, err := fixture.db.Exec(`UPDATE certificates
		SET common_name = '../unsafe' WHERE id = 1`); err != nil {
		t.Fatalf("seed invalid synthetic certificate identity: %v", err)
	}
	if _, err := fixture.service.ViewSecret(
		context.Background(),
		1,
		"../unsafe",
		totpAdminActor(),
	); !errors.Is(err, ErrTOTPInvalidState) {
		t.Fatalf("path traversal certificate identity error = %v", err)
	}
}

func TestTOTPVerificationAndPersistentRateLimit(t *testing.T) {
	fixture := newTOTPTestFixture(t)
	seed, err := hexDecodeSyntheticSeed()
	if err != nil {
		t.Fatal("decode synthetic TOTP test vector")
	}
	validCode, err := generateTOTPCode(seed, totpTestNow)
	if err != nil {
		t.Fatal("generate synthetic TOTP test code")
	}
	if err := fixture.service.Verify(
		context.Background(),
		1,
		validCode,
		totpAdminActor(),
	); err != nil {
		t.Fatalf("verify valid synthetic TOTP code: %v", err)
	}
	var lastVerifiedAt sql.NullTime
	if err := fixture.db.QueryRow(`SELECT last_verified_at
		FROM totp_identities WHERE certificate_id = 1`).
		Scan(&lastVerifiedAt); err != nil || !lastVerifiedAt.Valid {
		t.Fatal("successful verification did not update last_verified_at")
	}

	invalidCode := differentTOTPCode(validCode)
	for attempt := 0; attempt < defaultTOTPFailureLimit; attempt++ {
		err := fixture.service.Verify(
			context.Background(),
			1,
			invalidCode,
			totpAdminActor(),
		)
		if !errors.Is(err, ErrTOTPCodeInvalid) {
			t.Fatalf("failed verification attempt %d returned %v", attempt+1, err)
		}
	}
	restarted, err := NewTOTPService(fixture.db, TOTPServiceConfig{
		OATHSecretsPath: fixture.oathPath,
		QRCodeDirectory: fixture.clientsDir,
		QRCodeBinary:    "/bin/false",
		Issuer:          "ZHISUAN",
	})
	if err != nil {
		t.Fatalf("recreate TOTP service: %v", err)
	}
	restarted.now = func() time.Time { return totpTestNow }
	restarted.qrGenerator = fixture.qrGenerator
	if err := restarted.Verify(
		context.Background(),
		1,
		validCode,
		totpAdminActor(),
	); !errors.Is(err, ErrTOTPRateLimited) {
		t.Fatalf("restarted rate limiter error = %v", err)
	}
	independentActor := totpAdminActor()
	independentActor.UserID = 3
	independentActor.SourceIP = "192.0.2.30"
	independentActor.RequestID = "totp-request-independent"
	if err := restarted.Verify(
		context.Background(),
		1,
		validCode,
		independentActor,
	); err != nil {
		t.Fatalf("independent rate-limit dimension was blocked: %v", err)
	}
	restarted.now = func() time.Time {
		return totpTestNow.Add(defaultTOTPFailureWindow + time.Second)
	}
	laterCode, err := generateTOTPCode(
		seed,
		totpTestNow.Add(defaultTOTPFailureWindow+time.Second),
	)
	if err != nil {
		t.Fatal("generate later synthetic TOTP code")
	}
	if err := restarted.Verify(
		context.Background(),
		1,
		laterCode,
		totpAdminActor(),
	); err != nil {
		t.Fatalf("verification after rate-limit window: %v", err)
	}
	assertTOTPAuditContainsNoSyntheticSecret(
		t,
		fixture.db,
		"",
		validCode,
	)
}

func TestTOTPVerificationUsesCurrentTimeStepOnly(t *testing.T) {
	fixture := newTOTPTestFixture(t)
	seed, err := hexDecodeSyntheticSeed()
	if err != nil {
		t.Fatal("decode synthetic TOTP boundary vector")
	}
	boundary := time.Unix(1_800_000_000, 0).UTC()
	fixture.service.now = func() time.Time { return boundary }
	currentCode, _ := generateTOTPCode(seed, boundary)
	if err := fixture.service.Verify(
		context.Background(),
		1,
		currentCode,
		totpAdminActor(),
	); err != nil {
		t.Fatalf("current-step boundary verification: %v", err)
	}
	previousCode, _ := generateTOTPCode(
		seed,
		boundary.Add(-time.Second),
	)
	if previousCode == currentCode {
		t.Fatal("synthetic boundary vector did not cross a TOTP step")
	}
	if err := fixture.service.Verify(
		context.Background(),
		1,
		previousCode,
		totpAdminActor(),
	); !errors.Is(err, ErrTOTPCodeInvalid) {
		t.Fatalf("previous-step TOTP code error = %v", err)
	}
}

func TestTOTPVerificationRejectsNonASCIISixDigitInput(t *testing.T) {
	for _, code := range []string{"", "12345", "1234567", "１２３４５６", "+12345", "123 45"} {
		t.Run("invalid-format", func(t *testing.T) {
			fixture := newTOTPTestFixture(t)
			if err := fixture.service.Verify(
				context.Background(),
				1,
				code,
				totpAdminActor(),
			); !errors.Is(err, ErrTOTPCodeFormat) {
				t.Fatalf("invalid TOTP code format error = %v", err)
			}
		})
	}
}

func TestTOTPResetIsIdempotentAndPreservesCertificate(t *testing.T) {
	fixture := newTOTPTestFixture(t)
	beforeOATH := readTestFile(t, fixture.oathPath)
	var beforeSerial, beforeFingerprint string
	if err := fixture.db.QueryRow(`SELECT serial_number, fingerprint
		FROM certificates WHERE id = 1`).
		Scan(&beforeSerial, &beforeFingerprint); err != nil {
		t.Fatalf("read certificate identity before reset: %v", err)
	}
	const firstKey = "reset-idempotency-key-0001"
	first, err := fixture.service.Reset(
		context.Background(),
		1,
		"totp-test-client",
		firstKey,
		totpAdminActor(),
	)
	if err != nil || first.OperationID <= 0 ||
		first.Base32Secret == "" || first.Recovered {
		t.Fatalf("first TOTP reset result is invalid: error=%v", err)
	}
	afterFirst := readTestFile(t, fixture.oathPath)
	if bytes.Equal(beforeOATH, afterFirst) {
		t.Fatal("successful TOTP reset did not replace the synthetic identity")
	}
	second, err := fixture.service.Reset(
		context.Background(),
		1,
		"totp-test-client",
		firstKey,
		totpAdminActor(),
	)
	if err != nil || !second.Recovered ||
		second.OperationID != first.OperationID ||
		second.Base32Secret != first.Base32Secret {
		t.Fatalf("idempotent TOTP reset recovery failed: error=%v", err)
	}
	if !bytes.Equal(afterFirst, readTestFile(t, fixture.oathPath)) {
		t.Fatal("idempotent TOTP reset generated a second identity")
	}
	third, err := fixture.service.Reset(
		context.Background(),
		1,
		"totp-test-client",
		"reset-idempotency-key-0003",
		totpAdminActor(),
	)
	if err != nil || third.OperationID == first.OperationID ||
		third.Base32Secret == first.Base32Secret {
		t.Fatalf("new idempotency key did not create a new reset: %v", err)
	}
	var afterSerial, afterFingerprint, issuer, status string
	var resetAt sql.NullTime
	if err := fixture.db.QueryRow(`SELECT
		c.serial_number, c.fingerprint, t.issuer, t.status, t.reset_at
		FROM certificates AS c
		JOIN totp_identities AS t ON t.certificate_id = c.id
		WHERE c.id = 1`).Scan(
		&afterSerial,
		&afterFingerprint,
		&issuer,
		&status,
		&resetAt,
	); err != nil {
		t.Fatalf("read reset metadata: %v", err)
	}
	if afterSerial != beforeSerial ||
		afterFingerprint != beforeFingerprint ||
		issuer != "ZHISUAN" ||
		status != "active" ||
		!resetAt.Valid {
		t.Fatal("TOTP reset changed certificate identity or missed metadata")
	}
	assertTestFileMode(t, fixture.oathPath, 0o600)
	assertTestFileMode(t, fixture.qrPath, 0o600)
	assertTOTPAuditContainsNoSyntheticSecret(
		t,
		fixture.db,
		first.Base32Secret,
		"",
	)
}

func TestTOTPResetInvalidatesOldSeedAndAcceptsNewSeed(t *testing.T) {
	fixture := newTOTPTestFixture(t)
	oldSeed, err := hexDecodeSyntheticSeed()
	if err != nil {
		t.Fatal("decode synthetic TOTP test vector")
	}
	oldCode, _ := generateTOTPCode(oldSeed, totpTestNow)
	if _, err := fixture.service.Reset(
		context.Background(),
		1,
		"totp-test-client",
		"reset-idempotency-key-0002",
		totpAdminActor(),
	); err != nil {
		t.Fatalf("reset synthetic TOTP identity: %v", err)
	}
	newSeed, err := fixture.service.readSeedForTest()
	if err != nil {
		t.Fatal("read new synthetic TOTP seed")
	}
	verificationTime := totpTestNow
	newCode, _ := generateTOTPCode(newSeed, verificationTime)
	for attempt := 0; attempt < 10 && newCode == oldCode; attempt++ {
		verificationTime = verificationTime.Add(totpTimeStepSeconds * time.Second)
		oldCode, _ = generateTOTPCode(oldSeed, verificationTime)
		newCode, _ = generateTOTPCode(newSeed, verificationTime)
	}
	if newCode == oldCode {
		t.Fatal("synthetic old and new TOTP vectors repeatedly collided")
	}
	fixture.service.now = func() time.Time { return verificationTime }
	if err := fixture.service.Verify(
		context.Background(),
		1,
		oldCode,
		totpAdminActor(),
	); !errors.Is(err, ErrTOTPCodeInvalid) {
		t.Fatalf("old synthetic TOTP code error = %v", err)
	}
	if err := fixture.service.Verify(
		context.Background(),
		1,
		newCode,
		totpAdminActor(),
	); err != nil {
		t.Fatalf("new synthetic TOTP code verification: %v", err)
	}
}

func TestTOTPResetFailureCompensatesFiles(t *testing.T) {
	tests := []struct {
		name   string
		inject func(*totpTestFixture)
	}{
		{
			name: "random source",
			inject: func(fixture *totpTestFixture) {
				fixture.service.random = failingTOTPReader{}
			},
		},
		{
			name: "QR generation",
			inject: func(fixture *totpTestFixture) {
				fixture.qrGenerator.fail = true
			},
		},
		{
			name: "first file replacement",
			inject: func(fixture *totpTestFixture) {
				fixture.service.replaceFile = func(_, _ string) error {
					return errors.New("synthetic first replacement failure")
				}
			},
		},
		{
			name: "second file replacement",
			inject: func(fixture *totpTestFixture) {
				replace := fixture.service.replaceFile
				calls := 0
				fixture.service.replaceFile = func(source, target string) error {
					calls++
					if calls == 2 {
						return errors.New("synthetic second replacement failure")
					}
					return replace(source, target)
				}
			},
		},
		{
			name: "success audit",
			inject: func(fixture *totpTestFixture) {
				fixture.service.beforeSuccessAudit = func() error {
					return errors.New("synthetic success audit failure")
				}
			},
		},
		{
			name: "database commit",
			inject: func(fixture *totpTestFixture) {
				fixture.service.beforeCommit = func() error {
					return errors.New("synthetic database commit failure")
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTOTPTestFixture(t)
			beforeOATH := readTestFile(t, fixture.oathPath)
			beforeQR := readTestFile(t, fixture.qrPath)
			test.inject(fixture)
			if _, err := fixture.service.Reset(
				context.Background(),
				1,
				"totp-test-client",
				"reset-failure-key-0001",
				totpAdminActor(),
			); err == nil {
				t.Fatal("fault-injected TOTP reset unexpectedly succeeded")
			}
			if !bytes.Equal(beforeOATH, readTestFile(t, fixture.oathPath)) ||
				!bytes.Equal(beforeQR, readTestFile(t, fixture.qrPath)) {
				t.Fatal("fault-injected TOTP reset did not restore original files")
			}
			var status string
			if err := fixture.db.QueryRow(`SELECT status
				FROM totp_reset_operations
				WHERE certificate_id = 1`).
				Scan(&status); err != nil || status != totpResetStatusFailed {
				t.Fatalf("failed reset operation status = %q, error = %v", status, err)
			}
		})
	}
}

func TestTOTPResetTemporaryFileFailureDoesNotChangeIdentity(t *testing.T) {
	fixture := newTOTPTestFixture(t)
	beforeOATH := readTestFile(t, fixture.oathPath)
	beforeQR := readTestFile(t, fixture.qrPath)
	for _, lockPath := range []string{
		fixture.service.fileLockPath,
		fixture.service.fileLockPath + ".certificate-1",
	} {
		lock, err := acquireTOTPFileLock(context.Background(), lockPath)
		if err != nil {
			t.Fatalf("prepare synthetic TOTP lock file: %v", err)
		}
		lock.release()
	}
	if err := os.Chmod(fixture.clientsDir, 0o500); err != nil {
		t.Fatalf("make synthetic client directory read-only: %v", err)
	}
	defer os.Chmod(fixture.clientsDir, 0o700)
	if _, err := fixture.service.Reset(
		context.Background(),
		1,
		"totp-test-client",
		"reset-temp-failure-key-01",
		totpAdminActor(),
	); err == nil {
		t.Fatal("TOTP reset with unwritable temporary directory succeeded")
	}
	if !bytes.Equal(beforeOATH, readTestFile(t, fixture.oathPath)) ||
		!bytes.Equal(beforeQR, readTestFile(t, fixture.qrPath)) {
		t.Fatal("temporary-file failure changed TOTP identity files")
	}
}

func TestTOTPResetCompensationFailureBlocksFurtherWrites(t *testing.T) {
	fixture := newTOTPTestFixture(t)
	replace := fixture.service.replaceFile
	calls := 0
	fixture.service.replaceFile = func(source, target string) error {
		calls++
		if calls == 2 {
			return errors.New("synthetic second replacement failure")
		}
		return replace(source, target)
	}
	fixture.service.beforeCompensation = func() error {
		return errors.New("synthetic compensation failure")
	}
	if _, err := fixture.service.Reset(
		context.Background(),
		1,
		"totp-test-client",
		"reset-compensation-key-01",
		totpAdminActor(),
	); !errors.Is(err, ErrTOTPCompensationRequired) {
		t.Fatalf("compensation failure error = %v", err)
	}
	var status string
	if err := fixture.db.QueryRow(`SELECT status
		FROM totp_reset_operations WHERE certificate_id = 1`).
		Scan(&status); err != nil ||
		status != totpResetStatusCompensationRequired {
		t.Fatalf("compensation-required status = %q, error = %v", status, err)
	}
	if _, err := fixture.service.Reset(
		context.Background(),
		1,
		"totp-test-client",
		"reset-compensation-key-02",
		totpAdminActor(),
	); !errors.Is(err, ErrTOTPCompensationRequired) {
		t.Fatalf("write after compensation failure error = %v", err)
	}
}

func TestTOTPResetRecoversPreparedOperationFromBackup(t *testing.T) {
	fixture := newTOTPTestFixture(t)
	const idempotencyKey = "prepared-recovery-key-001"
	result, err := fixture.db.Exec(`INSERT INTO totp_reset_operations (
		certificate_id, idempotency_key, request_id, status,
		created_at, updated_at
	) VALUES (1, ?, 'crashed-request', 'prepared', ?, ?)`,
		idempotencyKey,
		totpTestNow.Add(-time.Minute),
		totpTestNow.Add(-time.Minute),
	)
	if err != nil {
		t.Fatalf("seed prepared reset operation: %v", err)
	}
	operationID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read prepared operation ID: %v", err)
	}
	originalOATH := readTestFile(t, fixture.oathPath)
	if err := fixture.service.createResetBackup(
		operationID,
		"totp-test-client",
		originalOATH,
	); err != nil {
		t.Fatalf("create synthetic crash recovery backup: %v", err)
	}
	identities, err := parseOATHSecrets(originalOATH)
	if err != nil {
		t.Fatalf("parse synthetic pre-crash identities: %v", err)
	}
	changed, err := replaceOATHIdentity(
		identities,
		"totp-test@example.invalid",
		syntheticTOTPReplacementHex,
	)
	if err != nil {
		t.Fatalf("prepare synthetic partial replacement: %v", err)
	}
	if err := writeAtomicSecureFile(fixture.oathPath, changed); err != nil {
		t.Fatalf("write synthetic partial replacement: %v", err)
	}
	if err := os.WriteFile(fixture.qrPath, []byte("partial-png"), 0o600); err != nil {
		t.Fatalf("write synthetic partial QR replacement: %v", err)
	}

	resetResult, err := fixture.service.Reset(
		context.Background(),
		1,
		"totp-test-client",
		idempotencyKey,
		totpAdminActor(),
	)
	if err != nil || !resetResult.Recovered ||
		resetResult.OperationID != operationID {
		t.Fatalf("prepared reset recovery failed: error=%v", err)
	}
	var operationStatus string
	if err := fixture.db.QueryRow(`SELECT status
		FROM totp_reset_operations WHERE id = ?`, operationID).
		Scan(&operationStatus); err != nil ||
		operationStatus != totpResetStatusCompleted {
		t.Fatalf("recovered operation status = %q, error = %v", operationStatus, err)
	}
}

func TestConcurrentTOTPResetForSameCertificateHasOneExecutor(t *testing.T) {
	fixture := newTOTPTestFixture(t)
	fixture.qrGenerator.started = make(chan struct{}, 1)
	fixture.qrGenerator.release = make(chan struct{})
	firstResult := make(chan error, 1)
	go func() {
		_, err := fixture.service.Reset(
			context.Background(),
			1,
			"totp-test-client",
			"concurrent-reset-key-001",
			totpAdminActor(),
		)
		firstResult <- err
	}()
	select {
	case <-fixture.qrGenerator.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first concurrent reset did not reach QR generation")
	}
	if _, err := fixture.service.Reset(
		context.Background(),
		1,
		"totp-test-client",
		"concurrent-reset-key-002",
		totpAdminActor(),
	); !errors.Is(err, ErrTOTPResetConflict) {
		t.Fatalf("second concurrent reset error = %v", err)
	}
	close(fixture.qrGenerator.release)
	if err := <-firstResult; err != nil {
		t.Fatalf("first concurrent reset failed: %v", err)
	}
	var completed int
	if err := fixture.db.QueryRow(`SELECT COUNT(*)
		FROM totp_reset_operations WHERE status = 'completed'`).
		Scan(&completed); err != nil || completed != 1 {
		t.Fatalf("completed concurrent reset count = %d, error = %v", completed, err)
	}
}

func TestConcurrentTOTPResetForDifferentCertificatesIsSafe(t *testing.T) {
	fixture := newTOTPTestFixture(t)
	if _, err := fixture.db.Exec(`INSERT INTO certificates (
		id, common_name, serial_number, status
	) VALUES (2, 'totp-test-client-2', 'F2', 'valid')`); err != nil {
		t.Fatalf("seed second synthetic certificate: %v", err)
	}
	if _, err := fixture.db.Exec(`INSERT INTO totp_identities (
		certificate_id, tfa_name, issuer, status
	) VALUES (2, 'totp-test-2@example.invalid', 'ZHISUAN', 'active')`); err != nil {
		t.Fatalf("seed second synthetic TOTP identity: %v", err)
	}
	oathFile, err := os.OpenFile(
		fixture.oathPath,
		os.O_APPEND|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		t.Fatalf("open synthetic identity file for second certificate: %v", err)
	}
	if _, err := oathFile.WriteString(
		"totp-test-2@example.invalid:" + syntheticTOTPReplacementHex + "\n",
	); err != nil {
		oathFile.Close()
		t.Fatalf("append second synthetic identity: %v", err)
	}
	if err := oathFile.Close(); err != nil {
		t.Fatalf("close synthetic identity file: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(fixture.clientsDir, "totp-test-client-2.png"),
		[]byte("synthetic-old-png-2"),
		0o600,
	); err != nil {
		t.Fatalf("write second synthetic QR code: %v", err)
	}

	fixture.qrGenerator.started = make(chan struct{}, 1)
	fixture.qrGenerator.release = make(chan struct{})
	firstResult := make(chan error, 1)
	secondResult := make(chan error, 1)
	go func() {
		_, err := fixture.service.Reset(
			context.Background(),
			1,
			"totp-test-client",
			"different-cert-reset-key-01",
			totpAdminActor(),
		)
		firstResult <- err
	}()
	select {
	case <-fixture.qrGenerator.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first different-certificate reset did not start")
	}
	go func() {
		_, err := fixture.service.Reset(
			context.Background(),
			2,
			"totp-test-client-2",
			"different-cert-reset-key-02",
			totpAdminActor(),
		)
		secondResult <- err
	}()
	close(fixture.qrGenerator.release)
	if err := <-firstResult; err != nil {
		t.Fatalf("first different-certificate reset failed: %v", err)
	}
	if err := <-secondResult; err != nil {
		t.Fatalf("second different-certificate reset failed: %v", err)
	}
	var completed int
	if err := fixture.db.QueryRow(`SELECT COUNT(*)
		FROM totp_reset_operations WHERE status = 'completed'`).
		Scan(&completed); err != nil || completed != 2 {
		t.Fatalf(
			"different-certificate completed reset count = %d, error = %v",
			completed,
			err,
		)
	}
}

func (s *TOTPService) readSeedForTest() ([]byte, error) {
	lock, err := acquireTOTPFileLock(context.Background(), s.fileLockPath)
	if err != nil {
		return nil, err
	}
	defer lock.release()
	return s.readSeedLocked("totp-test@example.invalid")
}

func hexDecodeSyntheticSeed() ([]byte, error) {
	identities, err := parseOATHSecrets(
		[]byte("totp-test@example.invalid:" + syntheticTOTPSeedHex + "\n"),
	)
	if err != nil {
		return nil, err
	}
	identity, err := findOATHIdentity(
		identities,
		"totp-test@example.invalid",
	)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(identity.HexSeed)
}

func differentTOTPCode(code string) string {
	if len(code) != 6 {
		return "000000"
	}
	replacement := byte('0')
	if code[0] == replacement {
		replacement = '1'
	}
	return string(replacement) + code[1:]
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read synthetic test file: %v", err)
	}
	return data
}

func assertTestFileMode(t *testing.T, path string, expected os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("inspect synthetic test file mode: %v", err)
	}
	if info.Mode().Perm() != expected {
		t.Fatalf(
			"synthetic test file mode = %o, want %o",
			info.Mode().Perm(),
			expected,
		)
	}
}

func assertTOTPAuditContainsNoSyntheticSecret(
	t *testing.T,
	db *sql.DB,
	base32Secret string,
	code string,
) {
	t.Helper()
	rows, err := db.Query(`SELECT summary, error_summary
		FROM audit_logs WHERE action LIKE 'totp.%'`)
	if err != nil {
		t.Fatalf("read TOTP audit summaries: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var summary, errorSummary string
		if err := rows.Scan(&summary, &errorSummary); err != nil {
			t.Fatalf("scan TOTP audit summary: %v", err)
		}
		combined := summary + "\n" + errorSummary
		if strings.Contains(combined, syntheticTOTPSeedHex) ||
			(base32Secret != "" && strings.Contains(combined, base32Secret)) ||
			(code != "" && strings.Contains(combined, code)) {
			t.Fatal("TOTP audit contained synthetic sensitive test material")
		}
	}
}
