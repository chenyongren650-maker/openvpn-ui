package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
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
