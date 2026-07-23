package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/d3vilh/openvpn-ui/migrations"
)

func TestParseCertificateIndexSupportsCertificateHistory(t *testing.T) {
	now := time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)
	index := strings.Join([]string{
		"V\t270101000000Z\t\t0a\tunknown\t/C=CN/O=Test/CN=test\\/client/name=test-client/LocalIP=dynamic.pool/2FAName=test-user@example.invalid",
		"R\t270101000000Z\t260701010203Z,keyCompromise\t0B\tunknown\t/C=CN/O=Test/CN=test-client/name=test-client/LocalIP=10.250.71.10",
		"V\t260101000000Z\t\t0C\tunknown\t/C=CN/O=Test/CN=expired-client/name=expired-client/LocalIP=none",
		"V\t20510101000000Z\t\t0D\tunknown\t/C=CN/O=Test/CN=long-lived-client/name=long-lived-client",
	}, "\n")

	records, err := parseCertificateIndex(strings.NewReader(index), now)
	if err != nil {
		t.Fatalf("parse certificate index: %v", err)
	}
	if len(records) != 4 {
		t.Fatalf("record count = %d, want 4", len(records))
	}

	if records[0].CommonName != "test/client" || records[0].SerialNumber != "0A" ||
		records[0].Status != "valid" || records[0].StaticIP != nil {
		t.Fatalf("unexpected valid certificate metadata: %+v", records[0])
	}
	if records[1].CommonName != "test-client" || records[1].Status != "revoked" ||
		records[1].StaticIP == nil || *records[1].StaticIP != "10.250.71.10" ||
		records[1].RevokedAt == nil {
		t.Fatalf("unexpected revoked certificate metadata: %+v", records[1])
	}
	if records[2].Status != "expired" {
		t.Fatalf("past valid certificate status = %q, want expired", records[2].Status)
	}
	if records[3].TechnicalExpiresAt.Year() != 2051 {
		t.Fatalf("generalized expiration year = %d, want 2051", records[3].TechnicalExpiresAt.Year())
	}
}

func TestParseCertificateIndexRejectsInvalidInputWithoutExposingLine(t *testing.T) {
	now := time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		index string
		want  string
	}{
		{
			name:  "wrong field count",
			index: "V\t270101000000Z\t\t01\tunknown",
			want:  "has 5 fields, want 6",
		},
		{
			name:  "unsupported status",
			index: "X\t270101000000Z\t\t01\tunknown\t/CN=test-client",
			want:  "unsupported status",
		},
		{
			name:  "invalid serial",
			index: "V\t270101000000Z\t\tserial-secret-marker\tunknown\t/CN=test-client",
			want:  "invalid serial number",
		},
		{
			name: "duplicate serial",
			index: strings.Join([]string{
				"V\t270101000000Z\t\t0a\tunknown\t/CN=test-client",
				"R\t270101000000Z\t260101000000Z\t0A\tunknown\t/CN=test-client",
			}, "\n"),
			want: "duplicates serial",
		},
		{
			name:  "missing common name",
			index: "V\t270101000000Z\t\t01\tunknown\t/O=Test/name=test-client",
			want:  "has no common name",
		},
		{
			name:  "invalid static IP",
			index: "V\t270101000000Z\t\t01\tunknown\t/CN=test-client/LocalIP=not-an-ip",
			want:  "invalid static IP metadata",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseCertificateIndex(strings.NewReader(test.index), now)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want text %q", err, test.want)
			}
			if strings.Contains(err.Error(), test.index) {
				t.Fatal("parser error exposed the source index line")
			}
		})
	}
}

func TestImportCertificateMetadataFileIsReadOnlyAndIdempotent(t *testing.T) {
	db := openCertificateImportTestDatabase(t)
	defer db.Close()

	now := time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)
	indexContent := strings.Join([]string{
		"V\t270101000000Z\t\t01\tunknown\t/C=CN/O=Test/CN=test-client/name=test-client/LocalIP=dynamic.pool/2FAName=test-user@example.invalid",
		"R\t270101000000Z\t260701010203Z\t02\tunknown\t/C=CN/O=Test/CN=test-client/name=test-client/LocalIP=10.250.71.10/2FAName=test-user@example.invalid",
	}, "\n") + "\n"
	pkiDirectory := filepath.Join(t.TempDir(), "pki")
	if err := os.MkdirAll(pkiDirectory, 0o700); err != nil {
		t.Fatalf("create synthetic test PKI directory: %v", err)
	}
	indexPath := filepath.Join(pkiDirectory, "index.txt")
	if err := os.WriteFile(indexPath, []byte(indexContent), 0o400); err != nil {
		t.Fatalf("create read-only synthetic certificate index: %v", err)
	}
	beforeHash := sha256.Sum256([]byte(indexContent))

	first, err := importCertificateMetadataFile(context.Background(), db, indexPath, now)
	if err != nil {
		t.Fatalf("first certificate metadata import: %v", err)
	}
	if first.Inserted != 2 || first.Updated != 0 || first.Unchanged != 0 {
		t.Fatalf("first import result = %+v", first)
	}

	second, err := importCertificateMetadataFile(context.Background(), db, indexPath, now)
	if err != nil {
		t.Fatalf("second certificate metadata import: %v", err)
	}
	if second.Inserted != 0 || second.Updated != 0 || second.Unchanged != 2 {
		t.Fatalf("second import result = %+v", second)
	}

	afterContent, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read synthetic certificate index after import: %v", err)
	}
	if afterHash := sha256.Sum256(afterContent); afterHash != beforeHash {
		t.Fatal("certificate index changed during read-only import")
	}

	var certificateCount, totpIdentityCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM certificates`).Scan(&certificateCount); err != nil {
		t.Fatalf("count imported certificates: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM totp_identities`).Scan(&totpIdentityCount); err != nil {
		t.Fatalf("count TOTP identity metadata: %v", err)
	}
	if certificateCount != 2 || totpIdentityCount != 0 {
		t.Fatalf(
			"certificate count = %d, TOTP identity count = %d; want 2 and 0",
			certificateCount,
			totpIdentityCount,
		)
	}
}

func TestImportCertificateMetadataPreservesPlatformOwnedFields(t *testing.T) {
	db := openCertificateImportTestDatabase(t)
	defer db.Close()

	initialExpiry := time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)
	initial := []certificateMetadata{{
		CommonName:         "test-client",
		SerialNumber:       "A1",
		Status:             "valid",
		TechnicalExpiresAt: initialExpiry,
	}}
	if _, err := importCertificateMetadata(
		context.Background(),
		db,
		initial,
		time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC),
	); err != nil {
		t.Fatalf("seed certificate metadata: %v", err)
	}

	if _, err := db.Exec(`UPDATE certificates SET
		vpn_user_id = 42,
		status = 'archived',
		permission_type = 'restricted',
		validity_mode = 'custom',
		business_expires_at = '2027-02-01T00:00:00Z',
		device_note = 'preserve this note',
		archived_at = '2026-07-22T00:00:00Z'
	WHERE serial_number = 'A1'`); err != nil {
		t.Fatalf("set platform-owned certificate fields: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO certificates (
		common_name, serial_number, status
	) VALUES ('database-only-client', 'FF', 'valid')`); err != nil {
		t.Fatalf("seed database-only certificate: %v", err)
	}

	revokedAt := time.Date(2026, time.July, 20, 1, 2, 3, 0, time.UTC)
	staticIP := "10.250.71.10"
	updatedExpiry := time.Date(2028, time.January, 1, 0, 0, 0, 0, time.UTC)
	updated := []certificateMetadata{{
		CommonName:         "test-client-renewed-metadata",
		SerialNumber:       "a1",
		Status:             "revoked",
		StaticIP:           &staticIP,
		TechnicalExpiresAt: updatedExpiry,
		RevokedAt:          &revokedAt,
	}}
	result, err := importCertificateMetadata(
		context.Background(),
		db,
		updated,
		time.Date(2026, time.July, 23, 13, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("update certificate metadata: %v", err)
	}
	if result.Updated != 1 {
		t.Fatalf("update result = %+v, want one updated row", result)
	}

	var (
		commonName, status, permissionType, validityMode, deviceNote string
		vpnUserID                                                    int64
		storedStaticIP                                               sql.NullString
	)
	if err := db.QueryRow(`SELECT
		common_name, status, permission_type, validity_mode,
		device_note, vpn_user_id, static_ip
	FROM certificates WHERE serial_number = 'A1'`).Scan(
		&commonName,
		&status,
		&permissionType,
		&validityMode,
		&deviceNote,
		&vpnUserID,
		&storedStaticIP,
	); err != nil {
		t.Fatalf("read updated certificate metadata: %v", err)
	}
	if commonName != "test-client-renewed-metadata" || status != "archived" ||
		permissionType != "restricted" || validityMode != "custom" ||
		deviceNote != "preserve this note" || vpnUserID != 42 ||
		!storedStaticIP.Valid || storedStaticIP.String != staticIP {
		t.Fatalf("platform-owned fields were not preserved")
	}
	withoutIndexStaticIP := updated[0]
	withoutIndexStaticIP.StaticIP = nil
	withoutIndexStaticIP.TechnicalExpiresAt = updatedExpiry.AddDate(1, 0, 0)
	if _, err := importCertificateMetadata(
		context.Background(),
		db,
		[]certificateMetadata{withoutIndexStaticIP},
		time.Date(2026, time.July, 23, 14, 0, 0, 0, time.UTC),
	); err != nil {
		t.Fatalf("reconcile certificate without legacy static IP metadata: %v", err)
	}
	if err := db.QueryRow(`SELECT static_ip FROM certificates
		WHERE serial_number = 'A1'`).Scan(&storedStaticIP); err != nil {
		t.Fatalf("read preserved static IP after reconciliation: %v", err)
	}
	if !storedStaticIP.Valid || storedStaticIP.String != staticIP {
		t.Fatalf(
			"database-owned static IP after reconciliation = %v",
			storedStaticIP,
		)
	}

	var certificateCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM certificates`).Scan(&certificateCount); err != nil {
		t.Fatalf("count certificates after reconciliation: %v", err)
	}
	if certificateCount != 2 {
		t.Fatalf("certificate count = %d, want database-only row preserved", certificateCount)
	}
}

func TestImportCertificateMetadataRollsBackBatchOnDatabaseFailure(t *testing.T) {
	db := openCertificateImportTestDatabase(t)
	defer db.Close()

	if _, err := db.Exec(`CREATE TRIGGER reject_test_serial
		BEFORE INSERT ON certificates
		WHEN NEW.serial_number = '02'
		BEGIN
			SELECT RAISE(ABORT, 'forced test failure');
		END`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}

	records := []certificateMetadata{
		{
			CommonName:         "test-client-01",
			SerialNumber:       "01",
			Status:             "valid",
			TechnicalExpiresAt: time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			CommonName:         "test-client-02",
			SerialNumber:       "02",
			Status:             "valid",
			TechnicalExpiresAt: time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	if _, err := importCertificateMetadata(
		context.Background(),
		db,
		records,
		time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC),
	); err == nil {
		t.Fatal("expected forced database import failure")
	}

	var certificateCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM certificates`).Scan(&certificateCount); err != nil {
		t.Fatalf("count certificates after rollback: %v", err)
	}
	if certificateCount != 0 {
		t.Fatalf("certificate count after rollback = %d, want 0", certificateCount)
	}
}

func TestImportCertificateMetadataFileAllowsMissingTestIndex(t *testing.T) {
	db := openCertificateImportTestDatabase(t)
	defer db.Close()

	result, err := importCertificateMetadataFile(
		context.Background(),
		db,
		filepath.Join(t.TempDir(), "pki", "index.txt"),
		time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("missing certificate index: %v", err)
	}
	if !reflect.DeepEqual(result, CertificateImportResult{SourceMissing: true}) {
		t.Fatalf("missing index result = %+v", result)
	}
}

func openCertificateImportTestDatabase(t *testing.T) *sql.DB {
	t.Helper()
	databasePath := filepath.Join(t.TempDir(), "db", "data.db")
	if _, err := migrations.Up(context.Background(), databasePath); err != nil {
		t.Fatalf("initialize certificate import database: %v", err)
	}

	dsn := fmt.Sprintf("file:%s?_busy_timeout=5000&_foreign_keys=on", databasePath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("open certificate import database: %v", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		t.Fatalf("connect to certificate import database: %v", err)
	}
	return db
}
