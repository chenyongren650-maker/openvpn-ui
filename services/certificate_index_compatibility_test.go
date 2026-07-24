package services

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRevokeNormalizesLegacyIndexMetadataWithBackup(t *testing.T) {
	service, db, pkiDir, runner, _ := newLifecycleTestService(
		t,
		"valid",
		"legacy-client",
		"A1",
		"",
	)
	defer db.Close()
	seedLegacyCertificateMetadata(
		t,
		db,
		"10.250.71.10",
		"legacy-user@example.invalid",
	)

	unrelatedLine := syntheticIndexLine(
		"valid",
		"unrelated-client",
		"B2",
	)
	legacyLine := strings.TrimSuffix(
		syntheticIndexLine("valid", "legacy-client", "A1"),
		"\n",
	) + "/name=legacy-client/LocalIP=10.250.71.10" +
		"/2FAName=legacy-user@example.invalid\n"
	indexBefore := []byte(unrelatedLine + legacyLine)
	indexPath := filepath.Join(pkiDir, "index.txt")
	if err := os.WriteFile(indexPath, indexBefore, 0o600); err != nil {
		t.Fatalf("write legacy certificate index: %v", err)
	}

	result, err := service.RevokeCertificate(
		context.Background(),
		1,
		"legacy-client",
		adminLifecycleActor(),
	)
	if err != nil || result.AlreadyRevoked {
		t.Fatalf("revoke legacy certificate = %+v, error = %v", result, err)
	}
	indexAfter, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read normalized certificate index: %v", err)
	}
	if !strings.HasPrefix(string(indexAfter), unrelatedLine) {
		t.Fatal("legacy normalization changed an unrelated certificate record")
	}
	if strings.Contains(string(indexAfter), "/name=legacy-client") ||
		strings.Contains(string(indexAfter), "/LocalIP=") ||
		strings.Contains(string(indexAfter), "/2FAName=") {
		t.Fatalf("legacy metadata remains in normalized index: %q", indexAfter)
	}
	targetFields := strings.Split(
		strings.TrimSpace(strings.Split(string(indexAfter), "\n")[1]),
		"\t",
	)
	if len(targetFields) != 6 || targetFields[0] != "R" {
		t.Fatalf("normalized legacy target was not revoked: %q", indexAfter)
	}

	backupDirectory := filepath.Join(
		pkiDir,
		"index-compatibility-backups",
	)
	backupEntries, err := os.ReadDir(backupDirectory)
	if err != nil {
		t.Fatalf("read index compatibility backups: %v", err)
	}
	if len(backupEntries) != 1 {
		t.Fatalf("index compatibility backup count = %d, want 1", len(backupEntries))
	}
	backupData, err := os.ReadFile(
		filepath.Join(backupDirectory, backupEntries[0].Name()),
	)
	if err != nil {
		t.Fatalf("read index compatibility backup: %v", err)
	}
	if string(backupData) != string(indexBefore) {
		t.Fatal("index compatibility backup does not match the original index")
	}
	if info, err := os.Stat(backupDirectory); err != nil ||
		info.Mode().Perm() != 0o700 {
		t.Fatalf("index compatibility backup directory is not mode 0700: %v", err)
	}

	retry, err := service.RevokeCertificate(
		context.Background(),
		1,
		"legacy-client",
		adminLifecycleActor(),
	)
	if err != nil || !retry.AlreadyRevoked {
		t.Fatalf("legacy revoke retry = %+v, error = %v", retry, err)
	}
	retryEntries, err := os.ReadDir(backupDirectory)
	if err != nil {
		t.Fatalf("read index compatibility backups after retry: %v", err)
	}
	if len(retryEntries) != 1 {
		t.Fatalf(
			"legacy revoke retry created %d backups, want 1",
			len(retryEntries),
		)
	}
	if revoke, genCRL := runner.commandCounts(); revoke != 1 || genCRL != 1 {
		t.Fatalf(
			"legacy revoke command counts: revoke=%d gen-crl=%d",
			revoke,
			genCRL,
		)
	}
}

func TestRevokeRejectsMismatchedLegacyIndexMetadataWithoutMutation(
	t *testing.T,
) {
	service, db, pkiDir, runner, _ := newLifecycleTestService(
		t,
		"valid",
		"legacy-mismatch-client",
		"A1",
		"",
	)
	defer db.Close()
	seedLegacyCertificateMetadata(
		t,
		db,
		"10.250.71.10",
		"legacy-user@example.invalid",
	)

	indexPath := filepath.Join(pkiDir, "index.txt")
	indexBefore := []byte(strings.TrimSuffix(
		syntheticIndexLine("valid", "legacy-mismatch-client", "A1"),
		"\n",
	) + "/name=legacy-mismatch-client/LocalIP=10.250.71.99" +
		"/2FAName=legacy-user@example.invalid\n")
	if err := os.WriteFile(indexPath, indexBefore, 0o600); err != nil {
		t.Fatalf("write mismatched legacy certificate index: %v", err)
	}

	_, err := service.RevokeCertificate(
		context.Background(),
		1,
		"legacy-mismatch-client",
		adminLifecycleActor(),
	)
	if !errors.Is(err, ErrCertificateIndexCompatibility) {
		t.Fatalf("mismatched legacy revoke error = %v", err)
	}
	indexAfter, readErr := os.ReadFile(indexPath)
	if readErr != nil {
		t.Fatalf("read mismatched legacy certificate index: %v", readErr)
	}
	if string(indexAfter) != string(indexBefore) {
		t.Fatal("mismatched legacy metadata changed the certificate index")
	}
	if _, statErr := os.Stat(
		filepath.Join(pkiDir, "index-compatibility-backups"),
	); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("mismatched legacy metadata created a backup: %v", statErr)
	}
	if revoke, genCRL := runner.commandCounts(); revoke != 0 || genCRL != 0 {
		t.Fatalf(
			"mismatched legacy metadata executed Easy-RSA: revoke=%d gen-crl=%d",
			revoke,
			genCRL,
		)
	}
	assertLatestAuditError(t, db, "index_compatibility_failed")
}

func TestRevokeStopsBeforeIndexMutationWhenCompatibilityBackupFails(
	t *testing.T,
) {
	service, db, pkiDir, runner, _ := newLifecycleTestService(
		t,
		"valid",
		"legacy-backup-client",
		"A1",
		"",
	)
	defer db.Close()
	seedLegacyCertificateMetadata(t, db, "", "")

	indexPath := filepath.Join(pkiDir, "index.txt")
	indexBefore := []byte(strings.TrimSuffix(
		syntheticIndexLine("valid", "legacy-backup-client", "A1"),
		"\n",
	) + "/name=legacy-backup-client/LocalIP=dynamic.pool/2FAName=none\n")
	if err := os.WriteFile(indexPath, indexBefore, 0o600); err != nil {
		t.Fatalf("write backup-failure legacy certificate index: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(pkiDir, "index-compatibility-backups"),
		[]byte("block compatibility backup directory"),
		0o600,
	); err != nil {
		t.Fatalf("block index compatibility backup directory: %v", err)
	}

	_, err := service.RevokeCertificate(
		context.Background(),
		1,
		"legacy-backup-client",
		adminLifecycleActor(),
	)
	if !errors.Is(err, ErrCertificateIndexCompatibility) {
		t.Fatalf("compatibility backup failure error = %v", err)
	}
	indexAfter, readErr := os.ReadFile(indexPath)
	if readErr != nil {
		t.Fatalf("read index after compatibility backup failure: %v", readErr)
	}
	if string(indexAfter) != string(indexBefore) {
		t.Fatal("compatibility backup failure changed the certificate index")
	}
	if revoke, genCRL := runner.commandCounts(); revoke != 0 || genCRL != 0 {
		t.Fatalf(
			"compatibility backup failure executed Easy-RSA: revoke=%d gen-crl=%d",
			revoke,
			genCRL,
		)
	}
}

func TestRevokeRetryAfterLegacyCommandFailureDoesNotRepeatNormalization(
	t *testing.T,
) {
	service, db, pkiDir, runner, _ := newLifecycleTestService(
		t,
		"valid",
		"legacy-retry-client",
		"A1",
		"",
	)
	defer db.Close()
	seedLegacyCertificateMetadata(t, db, "", "")

	indexPath := filepath.Join(pkiDir, "index.txt")
	indexBefore := []byte(strings.TrimSuffix(
		syntheticIndexLine("valid", "legacy-retry-client", "A1"),
		"\n",
	) + "/name=legacy-retry-client/LocalIP=dynamic.pool/2FAName=none\n")
	if err := os.WriteFile(indexPath, indexBefore, 0o600); err != nil {
		t.Fatalf("write retry legacy certificate index: %v", err)
	}
	runner.failNextRevoke = 1

	if _, err := service.RevokeCertificate(
		context.Background(),
		1,
		"legacy-retry-client",
		adminLifecycleActor(),
	); !errors.Is(err, ErrCertificateCommand) {
		t.Fatalf("first legacy revoke error = %v", err)
	}
	indexAfterFailure, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read normalized index after command failure: %v", err)
	}
	if strings.Contains(string(indexAfterFailure), "/LocalIP=") {
		t.Fatal("successful compatibility normalization was rolled back")
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM certificates WHERE id = 1`).
		Scan(&status); err != nil {
		t.Fatalf("read database state after legacy command failure: %v", err)
	}
	if status != "valid" {
		t.Fatalf("database status after legacy command failure = %q", status)
	}

	result, err := service.RevokeCertificate(
		context.Background(),
		1,
		"legacy-retry-client",
		adminLifecycleActor(),
	)
	if err != nil || result.AlreadyRevoked {
		t.Fatalf("legacy revoke retry = %+v, error = %v", result, err)
	}
	backupEntries, err := os.ReadDir(filepath.Join(
		pkiDir,
		"index-compatibility-backups",
	))
	if err != nil {
		t.Fatalf("read retry compatibility backups: %v", err)
	}
	if len(backupEntries) != 1 {
		t.Fatalf(
			"legacy command retry backup count = %d, want 1",
			len(backupEntries),
		)
	}
	if revoke, genCRL := runner.commandCounts(); revoke != 2 || genCRL != 1 {
		t.Fatalf(
			"legacy command retry counts: revoke=%d gen-crl=%d",
			revoke,
			genCRL,
		)
	}
}

func TestRevokeRejectsLegacyIndexSubjectMismatchBeforeBackup(t *testing.T) {
	service, db, pkiDir, runner, _ := newLifecycleTestService(
		t,
		"valid",
		"legacy-subject-client",
		"A1",
		"",
	)
	defer db.Close()
	seedLegacyCertificateMetadata(t, db, "", "")

	indexPath := filepath.Join(pkiDir, "index.txt")
	indexBefore := []byte(
		"V\t270723120000Z\t\tA1\tunknown\t" +
			"/C=US/O=Test/CN=legacy-subject-client" +
			"/name=legacy-subject-client/LocalIP=dynamic.pool/2FAName=none\n",
	)
	if err := os.WriteFile(indexPath, indexBefore, 0o600); err != nil {
		t.Fatalf("write subject-mismatch legacy certificate index: %v", err)
	}

	_, err := service.RevokeCertificate(
		context.Background(),
		1,
		"legacy-subject-client",
		adminLifecycleActor(),
	)
	if !errors.Is(err, ErrCertificateIndexCompatibility) {
		t.Fatalf("legacy subject mismatch error = %v", err)
	}
	indexAfter, readErr := os.ReadFile(indexPath)
	if readErr != nil {
		t.Fatalf("read legacy subject mismatch index: %v", readErr)
	}
	if string(indexAfter) != string(indexBefore) {
		t.Fatal("legacy subject mismatch changed the certificate index")
	}
	if _, statErr := os.Stat(filepath.Join(
		pkiDir,
		"index-compatibility-backups",
	)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("legacy subject mismatch created a backup: %v", statErr)
	}
	if revoke, genCRL := runner.commandCounts(); revoke != 0 || genCRL != 0 {
		t.Fatalf(
			"legacy subject mismatch executed Easy-RSA: revoke=%d gen-crl=%d",
			revoke,
			genCRL,
		)
	}
}

func seedLegacyCertificateMetadata(
	t *testing.T,
	db *sql.DB,
	staticIP string,
	tfaName string,
) {
	t.Helper()
	staticIPValue := any(nil)
	if staticIP != "" {
		staticIPValue = staticIP
	}
	if _, err := db.Exec(
		`UPDATE certificates SET static_ip = ? WHERE id = 1`,
		staticIPValue,
	); err != nil {
		t.Fatalf("seed legacy certificate static IP metadata: %v", err)
	}
	if tfaName == "" {
		return
	}
	if _, err := db.Exec(`INSERT INTO totp_identities (
		certificate_id, tfa_name, issuer, status, created_at
	) VALUES (1, ?, 'ZHISUAN', 'active', ?)`,
		tfaName,
		lifecycleTestNow,
	); err != nil {
		t.Fatalf("seed legacy certificate 2FA identity metadata: %v", err)
	}
}
