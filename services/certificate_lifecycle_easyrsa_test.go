package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/d3vilh/openvpn-ui/migrations"
)

// This integration test is opt-in because it requires the Easy-RSA executable.
// Validation runs it inside a disposable Docker test image; it never references
// host or production PKI paths.
func TestEasyRSARevokeAndArchiveAgainstIsolatedPKI(t *testing.T) {
	if os.Getenv("RUN_EASYRSA_INTEGRATION") != "1" {
		t.Skip("set RUN_EASYRSA_INTEGRATION=1 inside the isolated Docker test image")
	}
	binary := os.Getenv("EASYRSA_TEST_BINARY")
	if binary == "" {
		binary = "/usr/share/easy-rsa/easyrsa"
	}
	absoluteBinary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatalf("resolve Easy-RSA test binary: %v", err)
	}
	if _, err := os.Stat(absoluteBinary); err != nil {
		t.Fatalf("Easy-RSA test binary is unavailable: %v", err)
	}

	root := t.TempDir()
	pkiDir := filepath.Join(root, "isolated-test-pki")
	runIsolatedEasyRSA(t, absoluteBinary, pkiDir, "init-pki")
	runIsolatedEasyRSA(t, absoluteBinary, pkiDir, "build-ca", "nopass")
	runIsolatedEasyRSA(
		t,
		absoluteBinary,
		pkiDir,
		"build-client-full",
		"lifecycle-test-client",
		"nopass",
	)
	runIsolatedEasyRSA(t, absoluteBinary, pkiDir, "gen-crl")

	databasePath := filepath.Join(root, "db", "data.db")
	if _, err := migrations.Up(context.Background(), databasePath); err != nil {
		t.Fatalf("initialize isolated lifecycle database: %v", err)
	}
	db, err := sql.Open(
		"sqlite3",
		"file:"+databasePath+"?_busy_timeout=5000&_foreign_keys=on",
	)
	if err != nil {
		t.Fatalf("open isolated lifecycle database: %v", err)
	}
	defer db.Close()
	if _, err := ImportCertificateMetadataFile(
		context.Background(),
		db,
		filepath.Join(pkiDir, "index.txt"),
	); err != nil {
		t.Fatalf("import isolated Easy-RSA certificate metadata: %v", err)
	}

	var certificateID int64
	if err := db.QueryRow(`SELECT id FROM certificates
		WHERE common_name = 'lifecycle-test-client' AND status = 'valid'`).
		Scan(&certificateID); err != nil {
		t.Fatalf("read isolated certificate database ID: %v", err)
	}
	service, err := NewCertificateLifecycleService(
		db,
		CertificateLifecycleConfig{
			EasyRSABinary:     absoluteBinary,
			EasyRSAWorkingDir: filepath.Dir(absoluteBinary),
			PKIDir:            pkiDir,
		},
	)
	if err != nil {
		t.Fatalf("create isolated Easy-RSA lifecycle service: %v", err)
	}
	service.disconnector = &fakeLifecycleDisconnector{}

	renewalResult, err := service.RenewCertificate(
		context.Background(),
		certificateID,
		adminLifecycleActor(),
	)
	if err != nil {
		var errorSummary string
		if auditErr := db.QueryRow(`SELECT error_summary FROM audit_logs
			WHERE action = ?
			ORDER BY id DESC LIMIT 1`,
			CertificateAuditActionRenew,
		).Scan(&errorSummary); auditErr != nil {
			errorSummary = "audit_unavailable"
		}
		t.Fatalf(
			"renew isolated Easy-RSA certificate: %v (stage %s)",
			err,
			errorSummary,
		)
	}
	renewedCertificateID := renewalResult.NewCertificateID
	if renewedCertificateID <= 0 {
		t.Fatalf("renewed certificate database ID = %d", renewedCertificateID)
	}
	if _, err := service.DownloadableCertificate(
		context.Background(),
		certificateID,
	); !errors.Is(err, ErrCertificateDownloadBlocked) {
		t.Fatalf("historical renewed certificate download error = %v", err)
	}
	if _, err := service.DownloadableCertificate(
		context.Background(),
		renewedCertificateID,
	); err != nil {
		t.Fatalf("current renewed certificate is not downloadable: %v", err)
	}

	indexBefore := hashTestFile(t, filepath.Join(pkiDir, "index.txt"))
	crlBefore := hashTestFile(t, filepath.Join(pkiDir, "crl.pem"))
	if _, err := service.RevokeCertificate(
		context.Background(),
		certificateID,
		"lifecycle-test-client",
		adminLifecycleActor(),
	); err != nil {
		t.Fatalf("revoke isolated Easy-RSA certificate: %v", err)
	}
	indexAfterRevoke := hashTestFile(t, filepath.Join(pkiDir, "index.txt"))
	crlAfterRevoke := hashTestFile(t, filepath.Join(pkiDir, "crl.pem"))
	if indexAfterRevoke == indexBefore {
		t.Fatal("isolated Easy-RSA index did not change after revoke")
	}
	if crlAfterRevoke == crlBefore {
		t.Fatal("isolated Easy-RSA CRL did not change after revoke")
	}
	crlInfo, err := os.Stat(filepath.Join(pkiDir, "crl.pem"))
	if err != nil {
		t.Fatalf("stat isolated Easy-RSA CRL: %v", err)
	}
	if permissions := crlInfo.Mode().Perm(); permissions != 0o644 {
		t.Fatalf("isolated Easy-RSA CRL permissions = %04o, want 0644", permissions)
	}
	renewedState, err := service.loadCertificate(
		context.Background(),
		renewedCertificateID,
	)
	if err != nil {
		t.Fatalf("read current database state after historical revoke: %v", err)
	}
	currentRecord, err := service.loadPKICertificate(renewedState.SerialNumber)
	if err != nil {
		t.Fatalf("read current PKI certificate after historical revoke: %v", err)
	}
	if currentRecord.Status != "valid" {
		t.Fatalf(
			"historical revoke changed current renewed certificate status to %q",
			currentRecord.Status,
		)
	}

	pkiBeforeArchive := snapshotTestPKI(t, pkiDir)
	if _, err := service.ArchiveCertificate(
		context.Background(),
		certificateID,
		adminLifecycleActor(),
	); err != nil {
		t.Fatalf("archive isolated revoked certificate: %v", err)
	}
	pkiAfterArchive := snapshotTestPKI(t, pkiDir)
	if len(pkiBeforeArchive) != len(pkiAfterArchive) {
		t.Fatal("archive changed the isolated PKI file set")
	}
	for path, beforeHash := range pkiBeforeArchive {
		if pkiAfterArchive[path] != beforeHash {
			t.Fatalf("archive changed isolated PKI file %s", path)
		}
	}
}

func TestEasyRSARevokeNormalizesLegacyIndexMetadata(t *testing.T) {
	if os.Getenv("RUN_EASYRSA_INTEGRATION") != "1" {
		t.Skip("set RUN_EASYRSA_INTEGRATION=1 inside the isolated Docker test image")
	}
	binary := os.Getenv("EASYRSA_TEST_BINARY")
	if binary == "" {
		binary = "/usr/share/easy-rsa/easyrsa"
	}
	absoluteBinary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatalf("resolve Easy-RSA test binary: %v", err)
	}
	if _, err := os.Stat(absoluteBinary); err != nil {
		t.Fatalf("Easy-RSA test binary is unavailable: %v", err)
	}

	root := t.TempDir()
	pkiDir := filepath.Join(root, "isolated-legacy-test-pki")
	runIsolatedEasyRSA(t, absoluteBinary, pkiDir, "init-pki")
	runIsolatedEasyRSA(t, absoluteBinary, pkiDir, "build-ca", "nopass")
	runIsolatedEasyRSA(
		t,
		absoluteBinary,
		pkiDir,
		"build-client-full",
		"legacy-easyrsa-client",
		"nopass",
	)
	runIsolatedEasyRSA(t, absoluteBinary, pkiDir, "gen-crl")

	indexPath := filepath.Join(pkiDir, "index.txt")
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read isolated legacy Easy-RSA index: %v", err)
	}
	legacyIndexData := []byte(
		strings.TrimSuffix(string(indexData), "\n") +
			"/name=legacy-easyrsa-client/LocalIP=10.250.71.10" +
			"/2FAName=legacy-user@example.invalid\n",
	)
	if err := os.WriteFile(indexPath, legacyIndexData, 0o600); err != nil {
		t.Fatalf("prepare isolated legacy Easy-RSA index: %v", err)
	}

	databasePath := filepath.Join(root, "db", "data.db")
	if _, err := migrations.Up(context.Background(), databasePath); err != nil {
		t.Fatalf("initialize isolated legacy lifecycle database: %v", err)
	}
	db, err := sql.Open(
		"sqlite3",
		"file:"+databasePath+"?_busy_timeout=5000&_foreign_keys=on",
	)
	if err != nil {
		t.Fatalf("open isolated legacy lifecycle database: %v", err)
	}
	defer db.Close()
	if _, err := ImportCertificateMetadataFile(
		context.Background(),
		db,
		indexPath,
	); err != nil {
		t.Fatalf("import isolated legacy Easy-RSA metadata: %v", err)
	}

	var certificateID int64
	if err := db.QueryRow(`SELECT id FROM certificates
		WHERE common_name = 'legacy-easyrsa-client' AND status = 'valid'`).
		Scan(&certificateID); err != nil {
		t.Fatalf("read isolated legacy certificate database ID: %v", err)
	}
	service, err := NewCertificateLifecycleService(
		db,
		CertificateLifecycleConfig{
			EasyRSABinary:     absoluteBinary,
			EasyRSAWorkingDir: filepath.Dir(absoluteBinary),
			PKIDir:            pkiDir,
		},
	)
	if err != nil {
		t.Fatalf("create isolated legacy Easy-RSA lifecycle service: %v", err)
	}
	service.disconnector = &fakeLifecycleDisconnector{}

	indexBefore := hashTestFile(t, indexPath)
	crlBefore := hashTestFile(t, filepath.Join(pkiDir, "crl.pem"))
	if _, err := service.RevokeCertificate(
		context.Background(),
		certificateID,
		"legacy-easyrsa-client",
		adminLifecycleActor(),
	); err != nil {
		var errorSummary string
		_ = db.QueryRow(`SELECT error_summary FROM audit_logs
			WHERE action = ? ORDER BY id DESC LIMIT 1`,
			CertificateAuditActionRevoke,
		).Scan(&errorSummary)
		t.Fatalf(
			"revoke isolated legacy Easy-RSA certificate: %v (stage %s)",
			err,
			errorSummary,
		)
	}
	indexAfterData, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read normalized isolated legacy Easy-RSA index: %v", err)
	}
	if strings.Contains(string(indexAfterData), "/LocalIP=") ||
		strings.Contains(string(indexAfterData), "/2FAName=") ||
		strings.Contains(string(indexAfterData), "/name=legacy-easyrsa-client") {
		t.Fatalf(
			"isolated legacy Easy-RSA metadata was not normalized: %q",
			indexAfterData,
		)
	}
	if hashTestFile(t, indexPath) == indexBefore {
		t.Fatal("isolated legacy Easy-RSA index did not change after revoke")
	}
	if hashTestFile(t, filepath.Join(pkiDir, "crl.pem")) == crlBefore {
		t.Fatal("isolated legacy Easy-RSA CRL did not change after revoke")
	}

	backupEntries, err := os.ReadDir(
		filepath.Join(pkiDir, "index-compatibility-backups"),
	)
	if err != nil {
		t.Fatalf("read isolated legacy Easy-RSA backups: %v", err)
	}
	if len(backupEntries) != 1 {
		t.Fatalf(
			"isolated legacy Easy-RSA backup count = %d, want 1",
			len(backupEntries),
		)
	}
	backupData, err := os.ReadFile(filepath.Join(
		pkiDir,
		"index-compatibility-backups",
		backupEntries[0].Name(),
	))
	if err != nil {
		t.Fatalf("read isolated legacy Easy-RSA backup: %v", err)
	}
	if string(backupData) != string(legacyIndexData) {
		t.Fatal("isolated legacy Easy-RSA backup does not match original index")
	}

	var status, staticIP, tfaName, allocationStatus string
	if err := db.QueryRow(`SELECT c.status, c.static_ip, t.tfa_name
		FROM certificates AS c
		JOIN totp_identities AS t ON t.certificate_id = c.id
		WHERE c.id = ?`, certificateID).Scan(
		&status,
		&staticIP,
		&tfaName,
	); err != nil {
		t.Fatalf("read isolated legacy database state: %v", err)
	}
	if status != "revoked" ||
		staticIP != "10.250.71.10" ||
		tfaName != "legacy-user@example.invalid" {
		t.Fatalf(
			"isolated legacy database state: status=%q ip=%q tfa=%q",
			status,
			staticIP,
			tfaName,
		)
	}
	if err := db.QueryRow(`SELECT status FROM ip_allocations
		WHERE certificate_id = ?`, certificateID).Scan(
		&allocationStatus,
	); err != nil {
		t.Fatalf("read isolated legacy IP allocation: %v", err)
	}
	if allocationStatus != "pending_release" {
		t.Fatalf(
			"isolated legacy allocation status = %q, want pending_release",
			allocationStatus,
		)
	}

	pkiBeforeArchive := snapshotTestPKI(t, pkiDir)
	if _, err := service.ArchiveCertificate(
		context.Background(),
		certificateID,
		adminLifecycleActor(),
	); err != nil {
		t.Fatalf("archive isolated legacy certificate: %v", err)
	}
	if pkiAfterArchive := snapshotTestPKI(t, pkiDir); !reflect.DeepEqual(
		pkiBeforeArchive,
		pkiAfterArchive,
	) {
		t.Fatal("archive changed isolated legacy Easy-RSA PKI")
	}
}

func runIsolatedEasyRSA(
	t *testing.T,
	binary string,
	pkiDir string,
	args ...string,
) {
	t.Helper()
	commandArgs := append(
		[]string{"--batch", "--pki-dir=" + pkiDir},
		args...,
	)
	command := exec.Command(binary, commandArgs...)
	command.Dir = filepath.Dir(binary)
	command.Env = append(os.Environ(), "EASYRSA_BATCH=1")
	if args[0] == "build-ca" {
		command.Env = append(command.Env, "EASYRSA_REQ_CN=Isolated Lifecycle Test CA")
	}
	if err := command.Run(); err != nil {
		t.Fatalf("run isolated Easy-RSA command %s: %v", args[0], err)
	}
}

func hashTestFile(t *testing.T, path string) [sha256.Size]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read isolated test file %s: %v", filepath.Base(path), err)
	}
	return sha256.Sum256(data)
}
