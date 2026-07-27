package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var legacyTableNames = []string{
	"user",
	"settings",
	"o_v_config",
	"o_v_client_config",
	"easy_r_s_a_config",
}

func TestUpgradePreservesLegacyTablesAndCreatesFoundationSchema(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "db", "data.db")
	legacySchema := createLegacyDatabase(t, databasePath)

	result, err := run(context.Background(), databasePath, registeredMigrations, fixedClock)
	if err != nil {
		t.Fatalf("run migration: %v", err)
	}
	if !reflect.DeepEqual(result.AppliedVersions, []int64{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("applied versions = %v, want [1 2 3 4 5 6]", result.AppliedVersions)
	}
	if result.BackupPath == "" {
		t.Fatal("expected a pre-migration backup")
	}

	db := openTestDatabase(t, databasePath)
	defer db.Close()

	for _, tableName := range []string{
		"schema_migrations",
		"certificates",
		"totp_identities",
		"audit_logs",
		"ip_allocations",
		"vpn_users",
		"ip_allocation_reservations",
		"totp_reset_operations",
	} {
		assertTableExists(t, db, tableName, true)
	}
	assertLegacyDatabaseUnchanged(t, db, legacySchema)

	var migrationCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 1`).Scan(&migrationCount); err != nil {
		t.Fatalf("count migration rows: %v", err)
	}
	if migrationCount != 1 {
		t.Fatalf("migration row count = %d, want 1", migrationCount)
	}

	assertBackupIsValidPreMigrationDatabase(t, result.BackupPath, legacySchema)
	assertPathPermissions(t, filepath.Dir(result.BackupPath), 0o700)
	assertPathPermissions(t, result.BackupPath, 0o600)
}

func TestMigrationIsIdempotent(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "db", "data.db")
	createLegacyDatabase(t, databasePath)

	firstResult, err := run(context.Background(), databasePath, registeredMigrations, fixedClock)
	if err != nil {
		t.Fatalf("first migration run: %v", err)
	}
	secondResult, err := run(context.Background(), databasePath, registeredMigrations, fixedClock)
	if err != nil {
		t.Fatalf("second migration run: %v", err)
	}

	if !reflect.DeepEqual(firstResult.AppliedVersions, []int64{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("first applied versions = %v, want [1 2 3 4 5 6]", firstResult.AppliedVersions)
	}
	if len(secondResult.AppliedVersions) != 0 {
		t.Fatalf("second applied versions = %v, want none", secondResult.AppliedVersions)
	}
	if secondResult.BackupPath != "" {
		t.Fatalf("second run created unexpected backup %q", secondResult.BackupPath)
	}

	backupEntries, err := os.ReadDir(filepath.Join(filepath.Dir(databasePath), "backups"))
	if err != nil {
		t.Fatalf("read backup directory: %v", err)
	}
	if len(backupEntries) != 1 {
		t.Fatalf("backup count = %d, want 1", len(backupEntries))
	}

	db := openTestDatabase(t, databasePath)
	defer db.Close()
	var migrationCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&migrationCount); err != nil {
		t.Fatalf("count migration rows: %v", err)
	}
	if migrationCount != 6 {
		t.Fatalf("migration row count = %d, want 6", migrationCount)
	}
}

func TestConcurrentMigrationRunsApplyOnceAndCreateOneBackup(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "db", "data.db")
	createLegacyDatabase(t, databasePath)

	const runnerCount = 8
	results := make(chan Result, runnerCount)
	failures := make(chan error, runnerCount)
	var waitGroup sync.WaitGroup
	for index := 0; index < runnerCount; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			result, err := run(
				context.Background(),
				databasePath,
				registeredMigrations,
				fixedClock,
			)
			if err != nil {
				failures <- err
				return
			}
			results <- result
		}()
	}
	waitGroup.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Errorf("concurrent migration run: %v", err)
	}
	if t.Failed() {
		return
	}

	appliedRuns := 0
	backupRuns := 0
	for result := range results {
		if len(result.AppliedVersions) > 0 {
			appliedRuns++
			if !reflect.DeepEqual(
				result.AppliedVersions,
				[]int64{1, 2, 3, 4, 5, 6},
			) {
				t.Fatalf(
					"concurrent applied versions = %v",
					result.AppliedVersions,
				)
			}
		}
		if result.BackupPath != "" {
			backupRuns++
		}
	}
	if appliedRuns != 1 || backupRuns != 1 {
		t.Fatalf(
			"concurrent applied runs = %d, backup runs = %d; want 1 and 1",
			appliedRuns,
			backupRuns,
		)
	}

	db := openTestDatabase(t, databasePath)
	defer db.Close()
	var migrationCount int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM schema_migrations`,
	).Scan(&migrationCount); err != nil {
		t.Fatalf("count concurrent migration rows: %v", err)
	}
	if migrationCount != len(registeredMigrations) {
		t.Fatalf(
			"concurrent migration count = %d, want %d",
			migrationCount,
			len(registeredMigrations),
		)
	}
}

func TestCertificateHistoryCompatibilityMigrationPreservesMetadata(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "db", "data.db")
	if _, err := run(
		context.Background(),
		databasePath,
		registeredMigrations[:1],
		fixedClock,
	); err != nil {
		t.Fatalf("initialize v1 database: %v", err)
	}

	db := openTestDatabase(t, databasePath)
	if _, err := db.Exec(`INSERT INTO certificates (
		id, vpn_user_id, common_name, serial_number, fingerprint, status,
		permission_type, static_ip, validity_mode, business_expires_at,
		technical_expires_at, device_note, created_at, revoked_at, archived_at
	) VALUES (
		7, 42, 'test-client', 'a1', 'fingerprint-a1', 'valid',
		'restricted', '10.250.71.10', 'custom', '2027-01-01T00:00:00Z',
		'2027-01-02T00:00:00Z', 'test device', '2026-01-01T00:00:00Z', NULL, NULL
	)`); err != nil {
		db.Close()
		t.Fatalf("seed v1 certificate: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO totp_identities (
		id, certificate_id, tfa_name, issuer, status, created_at
	) VALUES (9, 7, 'test-user@example.invalid', 'TEST', 'active', '2026-01-01T00:00:00Z')`); err != nil {
		db.Close()
		t.Fatalf("seed v1 TOTP identity metadata: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close v1 database: %v", err)
	}

	result, err := run(
		context.Background(),
		databasePath,
		registeredMigrations[:2],
		fixedClock,
	)
	if err != nil {
		t.Fatalf("apply certificate compatibility migration: %v", err)
	}
	if !reflect.DeepEqual(result.AppliedVersions, []int64{2}) {
		t.Fatalf("applied versions = %v, want [2]", result.AppliedVersions)
	}
	if result.BackupPath == "" {
		t.Fatal("expected a pre-v2 backup")
	}

	db = openTestDatabase(t, databasePath)
	defer db.Close()

	var (
		commonName, serialNumber, fingerprint, status, permissionType string
		staticIP, validityMode, deviceNote, tfaName, issuer           string
		certificateID, totpID                                         int64
	)
	if err := db.QueryRow(`SELECT
		id, common_name, serial_number, fingerprint, status,
		permission_type, static_ip, validity_mode, device_note
	FROM certificates WHERE id = 7`).Scan(
		&certificateID,
		&commonName,
		&serialNumber,
		&fingerprint,
		&status,
		&permissionType,
		&staticIP,
		&validityMode,
		&deviceNote,
	); err != nil {
		t.Fatalf("read migrated certificate: %v", err)
	}
	if certificateID != 7 || commonName != "test-client" || serialNumber != "a1" ||
		fingerprint != "fingerprint-a1" || status != "valid" ||
		permissionType != "restricted" || staticIP != "10.250.71.10" ||
		validityMode != "custom" || deviceNote != "test device" {
		t.Fatalf("migrated certificate metadata changed unexpectedly")
	}

	if err := db.QueryRow(`SELECT id, certificate_id, tfa_name, issuer
		FROM totp_identities WHERE id = 9`).Scan(
		&totpID,
		&certificateID,
		&tfaName,
		&issuer,
	); err != nil {
		t.Fatalf("read migrated TOTP identity metadata: %v", err)
	}
	if totpID != 9 || certificateID != 7 ||
		tfaName != "test-user@example.invalid" || issuer != "TEST" {
		t.Fatalf("migrated TOTP identity metadata changed unexpectedly")
	}

	// Renewed certificate history must allow the same CN and static IP while
	// preserving the serial number as the stable unique identity.
	if _, err := db.Exec(`INSERT INTO certificates (
		common_name, serial_number, status, static_ip
	) VALUES ('test-client', 'A2', 'revoked', '10.250.71.10')`); err != nil {
		t.Fatalf("insert renewed certificate history: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO certificates (
		common_name, serial_number, status
	) VALUES ('another-client', 'A1', 'valid')`); err == nil {
		t.Fatal("expected case-insensitive duplicate serial number to fail")
	}

	var foreignKeyViolations int
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatalf("check foreign keys: %v", err)
	}
	for rows.Next() {
		foreignKeyViolations++
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close foreign key check rows: %v", err)
	}
	if foreignKeyViolations != 0 {
		t.Fatalf("foreign key violations = %d, want 0", foreignKeyViolations)
	}
}

func TestIPAllocationsMigrationSupportsPendingReleaseAndRollback(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "db", "data.db")
	if _, err := run(
		context.Background(),
		databasePath,
		registeredMigrations[:2],
		fixedClock,
	); err != nil {
		t.Fatalf("initialize v2 database: %v", err)
	}

	db := openTestDatabase(t, databasePath)
	for _, statement := range []string{
		`INSERT INTO certificates (
			id, common_name, serial_number, status, static_ip
		) VALUES (1, 'test-client-a', 'A1', 'valid', '10.250.71.10')`,
		`INSERT INTO certificates (
			id, common_name, serial_number, status, static_ip
		) VALUES (2, 'test-client-b', 'A2', 'revoked', '10.250.71.10')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			t.Fatalf("seed v2 certificate history: %v", err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close v2 database: %v", err)
	}

	result, err := run(
		context.Background(),
		databasePath,
		registeredMigrations[:3],
		fixedClock,
	)
	if err != nil {
		t.Fatalf("apply ip allocation migration: %v", err)
	}
	if !reflect.DeepEqual(result.AppliedVersions, []int64{3}) {
		t.Fatalf("applied versions = %v, want [3]", result.AppliedVersions)
	}
	if result.BackupPath == "" {
		t.Fatal("expected a verified pre-v3 backup")
	}

	db = openTestDatabase(t, databasePath)
	assertTableExists(t, db, "ip_allocations", true)
	if _, err := db.Exec(`INSERT INTO ip_allocations (
		ip_address, certificate_id, status, pending_release_at
	) VALUES ('10.250.71.10', 1, 'pending_release', '2026-07-23T00:00:00Z')`); err != nil {
		db.Close()
		t.Fatalf("insert pending-release allocation: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO ip_allocations (
		ip_address, certificate_id, status
	) VALUES ('10.250.71.10', 2, 'allocated')`); err == nil {
		db.Close()
		t.Fatal("expected duplicate active address allocation to fail")
	}
	if _, err := db.Exec(`INSERT INTO ip_allocations (
		ip_address, certificate_id, status, released_at
	) VALUES ('10.250.71.10', 2, 'released', '2026-07-23T00:00:00Z')`); err != nil {
		db.Close()
		t.Fatalf("preserve released address history: %v", err)
	}
	if _, err := db.Exec(`UPDATE ip_allocations SET status = 'invalid' WHERE certificate_id = 2`); err == nil {
		db.Close()
		t.Fatal("expected invalid allocation status to fail")
	}

	tx, err := db.Begin()
	if err != nil {
		db.Close()
		t.Fatalf("begin isolated rollback verification: %v", err)
	}
	for _, statement := range registeredMigrations[2].Down {
		if _, err := tx.Exec(statement); err != nil {
			tx.Rollback()
			db.Close()
			t.Fatalf("execute v3 rollback statement: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		db.Close()
		t.Fatalf("commit isolated rollback verification: %v", err)
	}
	assertTableExists(t, db, "ip_allocations", false)
	assertTableExists(t, db, "certificates", true)
	if err := db.Close(); err != nil {
		t.Fatalf("close migrated database: %v", err)
	}

	backupDB := openTestDatabase(t, result.BackupPath)
	defer backupDB.Close()
	assertTableExists(t, backupDB, "ip_allocations", false)
	assertTableExists(t, backupDB, "certificates", true)
}

func TestVPNUsersAndReservationMigrationsEnforceRelationships(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "db", "data.db")
	if _, err := run(
		context.Background(),
		databasePath,
		registeredMigrations[:3],
		fixedClock,
	); err != nil {
		t.Fatalf("initialize v3 database: %v", err)
	}

	result, err := run(context.Background(), databasePath, registeredMigrations, fixedClock)
	if err != nil {
		t.Fatalf("apply vpn user and reservation migrations: %v", err)
	}
	if !reflect.DeepEqual(result.AppliedVersions, []int64{4, 5, 6}) {
		t.Fatalf("applied versions = %v, want [4 5 6]", result.AppliedVersions)
	}
	if result.BackupPath == "" {
		t.Fatal("expected a verified pre-v4 backup")
	}

	db := openTestDatabase(t, databasePath)
	defer db.Close()
	assertTableExists(t, db, "vpn_users", true)
	assertTableExists(t, db, "ip_allocation_reservations", true)
	assertTableExists(t, db, "totp_reset_operations", true)

	if _, err := db.Exec(`INSERT INTO vpn_users (
		id, display_name, username, email, department, notes
	) VALUES (10, 'Test User', 'test-user', 'test-user@example.invalid', 'QA', '')`); err != nil {
		t.Fatalf("insert VPN user: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO vpn_users (
		display_name, username, email
	) VALUES ('Duplicate User', 'TEST-USER', 'other@example.invalid')`); err == nil {
		t.Fatal("expected case-insensitive duplicate username to fail")
	}
	if _, err := db.Exec(`INSERT INTO vpn_users (
		display_name, username, email
	) VALUES ('Duplicate Email', 'other-user', 'TEST-USER@EXAMPLE.INVALID')`); err == nil {
		t.Fatal("expected case-insensitive duplicate email to fail")
	}
	if _, err := db.Exec(`INSERT INTO certificates (
		id, vpn_user_id, common_name, serial_number, status
	) VALUES (20, 999, 'missing-user-client', 'B1', 'valid')`); err == nil {
		t.Fatal("expected missing VPN user relationship to fail")
	}
	if _, err := db.Exec(`INSERT INTO certificates (
		id, vpn_user_id, common_name, serial_number, status
	) VALUES (21, 10, 'test-user-client', 'B2', 'valid')`); err != nil {
		t.Fatalf("insert linked certificate: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM vpn_users WHERE id = 10`); err == nil {
		t.Fatal("expected linked VPN user deletion to fail")
	}

	if _, err := db.Exec(`INSERT INTO ip_allocation_reservations (
		ip_address, certificate_name, request_id, status
	) VALUES ('10.9.5.10', 'test-user-client', 'request-1', 'reserved')`); err != nil {
		t.Fatalf("insert active reservation: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO ip_allocation_reservations (
		ip_address, certificate_name, request_id, status
	) VALUES ('10.9.5.10', 'other-client', 'request-2', 'reserved')`); err == nil {
		t.Fatal("expected duplicate active IP reservation to fail")
	}
	if _, err := db.Exec(`INSERT INTO ip_allocation_reservations (
		ip_address, certificate_name, request_id, status
	) VALUES ('10.9.5.11', 'TEST-USER-CLIENT', 'request-3', 'reserved')`); err == nil {
		t.Fatal("expected duplicate active certificate reservation to fail")
	}
	if _, err := db.Exec(`UPDATE ip_allocation_reservations
		SET status = 'invalid' WHERE certificate_name = 'test-user-client'`); err == nil {
		t.Fatal("expected invalid reservation status to fail")
	}
}

func TestVPNUsersAndReservationDownSQLIsIsolatedAndReversible(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "db", "data.db")
	if _, err := run(context.Background(), databasePath, registeredMigrations, fixedClock); err != nil {
		t.Fatalf("initialize database: %v", err)
	}

	db := openTestDatabase(t, databasePath)
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin isolated rollback verification: %v", err)
	}
	for migrationIndex := len(registeredMigrations) - 1; migrationIndex >= 3; migrationIndex-- {
		for _, statement := range registeredMigrations[migrationIndex].Down {
			if _, err := tx.Exec(statement); err != nil {
				tx.Rollback()
				t.Fatalf(
					"execute v%d rollback statement: %v",
					registeredMigrations[migrationIndex].Version,
					err,
				)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit isolated rollback verification: %v", err)
	}
	assertTableExists(t, db, "ip_allocation_reservations", false)
	assertTableExists(t, db, "totp_reset_operations", false)
	assertTableExists(t, db, "vpn_users", false)
	assertTableExists(t, db, "certificates", true)
	assertTableExists(t, db, "ip_allocations", true)
}

func TestTOTPResetOperationsMigrationConstraintsAndRollback(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "db", "data.db")
	if _, err := run(
		context.Background(),
		databasePath,
		registeredMigrations[:5],
		fixedClock,
	); err != nil {
		t.Fatalf("initialize v5 database: %v", err)
	}
	db := openTestDatabase(t, databasePath)
	if _, err := db.Exec(`INSERT INTO certificates (
		id, common_name, serial_number, status
	) VALUES (1, 'totp-reset-client', 'E1', 'valid')`); err != nil {
		db.Close()
		t.Fatalf("seed v5 certificate: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close v5 database: %v", err)
	}

	result, err := run(
		context.Background(),
		databasePath,
		registeredMigrations,
		fixedClock,
	)
	if err != nil {
		t.Fatalf("apply TOTP reset migration: %v", err)
	}
	if !reflect.DeepEqual(result.AppliedVersions, []int64{6}) {
		t.Fatalf("applied versions = %v, want [6]", result.AppliedVersions)
	}
	if result.BackupPath == "" {
		t.Fatal("expected a verified pre-v6 backup")
	}

	db = openTestDatabase(t, databasePath)
	defer db.Close()
	assertTableExists(t, db, "totp_reset_operations", true)
	if _, err := db.Exec(`INSERT INTO totp_reset_operations (
		certificate_id, idempotency_key, request_id, status
	) VALUES (1, 'idempotency-key-0001', 'request-1', 'prepared')`); err != nil {
		t.Fatalf("insert prepared reset operation: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO totp_reset_operations (
		certificate_id, idempotency_key, request_id, status
	) VALUES (1, 'idempotency-key-0002', 'request-2', 'prepared')`); err == nil {
		t.Fatal("expected concurrent prepared reset operation to fail")
	}
	if _, err := db.Exec(`UPDATE totp_reset_operations
		SET status = 'completed', completed_at = CURRENT_TIMESTAMP
		WHERE certificate_id = 1`); err != nil {
		t.Fatalf("complete first reset operation: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO totp_reset_operations (
		certificate_id, idempotency_key, request_id, status
	) VALUES (1, 'idempotency-key-0002', 'request-2', 'prepared')`); err != nil {
		t.Fatalf("insert next reset operation: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO totp_reset_operations (
		certificate_id, idempotency_key, request_id, status
	) VALUES (999, 'idempotency-key-foreign', 'request-3', 'failed')`); err == nil {
		t.Fatal("expected missing certificate foreign key to fail")
	}
	if _, err := db.Exec(`UPDATE totp_reset_operations
		SET status = 'invalid' WHERE idempotency_key = 'idempotency-key-0002'`); err == nil {
		t.Fatal("expected invalid reset operation status to fail")
	}

	rows, err := db.Query(`PRAGMA table_info(totp_reset_operations)`)
	if err != nil {
		t.Fatalf("read TOTP reset operation columns: %v", err)
	}
	forbiddenColumns := map[string]bool{
		"seed":     true,
		"secret":   true,
		"code":     true,
		"password": true,
		"qr_uri":   true,
		"base32":   true,
		"hex_seed": true,
	}
	for rows.Next() {
		var columnID int
		var columnName, columnType string
		var notNull, primaryKey int
		var defaultValue sql.NullString
		if err := rows.Scan(
			&columnID,
			&columnName,
			&columnType,
			&notNull,
			&defaultValue,
			&primaryKey,
		); err != nil {
			rows.Close()
			t.Fatalf("scan TOTP reset operation column: %v", err)
		}
		if forbiddenColumns[strings.ToLower(columnName)] {
			rows.Close()
			t.Fatalf("sensitive column %q exists in TOTP reset operations", columnName)
		}
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close TOTP reset operation columns: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin isolated v6 rollback: %v", err)
	}
	for _, statement := range registeredMigrations[5].Down {
		if _, err := tx.Exec(statement); err != nil {
			tx.Rollback()
			t.Fatalf("execute v6 rollback statement: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit isolated v6 rollback: %v", err)
	}
	assertTableExists(t, db, "totp_reset_operations", false)
	assertTableExists(t, db, "totp_identities", true)
	assertTableExists(t, db, "certificates", true)
}

func TestFailedMigrationRollsBackEntirePendingBatch(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "db", "data.db")
	legacySchema := createLegacyDatabase(t, databasePath)

	failingMigrations := append([]Migration{}, registeredMigrations...)
	failingMigrations = append(failingMigrations, Migration{
		Version: 7,
		Name:    "forced_failure",
		Up: []string{
			`CREATE TABLE should_rollback (id INTEGER PRIMARY KEY)`,
			`CREATE TABL invalid_sql (id INTEGER PRIMARY KEY)`,
		},
		Down: []string{`DROP TABLE IF EXISTS should_rollback`},
	})

	result, err := run(context.Background(), databasePath, failingMigrations, fixedClock)
	if err == nil {
		t.Fatal("expected migration failure")
	}
	if !strings.Contains(err.Error(), "migration 7 (forced_failure), statement 2") {
		t.Fatalf("unexpected migration error: %v", err)
	}
	if len(result.AppliedVersions) != 0 {
		t.Fatalf("reported applied versions after rollback: %v", result.AppliedVersions)
	}
	if result.BackupPath == "" {
		t.Fatal("expected backup to be retained after migration failure")
	}

	db := openTestDatabase(t, databasePath)
	defer db.Close()
	for _, tableName := range []string{
		"schema_migrations",
		"certificates",
		"totp_identities",
		"audit_logs",
		"ip_allocations",
		"vpn_users",
		"ip_allocation_reservations",
		"totp_reset_operations",
		"should_rollback",
	} {
		assertTableExists(t, db, tableName, false)
	}
	assertLegacyDatabaseUnchanged(t, db, legacySchema)
	assertBackupIsValidPreMigrationDatabase(t, result.BackupPath, legacySchema)
}

func TestBackupFailureStopsBeforeMigration(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "db", "data.db")
	legacySchema := createLegacyDatabase(t, databasePath)
	backupDirectoryPath := filepath.Join(filepath.Dir(databasePath), "backups")
	if err := os.WriteFile(backupDirectoryPath, []byte("blocks backup directory"), 0o600); err != nil {
		t.Fatalf("create backup path blocker: %v", err)
	}

	result, err := run(context.Background(), databasePath, registeredMigrations, fixedClock)
	if err == nil {
		t.Fatal("expected backup failure")
	}
	if !strings.Contains(err.Error(), "back up SQLite database before migration") {
		t.Fatalf("unexpected backup error: %v", err)
	}
	if len(result.AppliedVersions) != 0 || result.BackupPath != "" {
		t.Fatalf("unexpected migration result after backup failure: %+v", result)
	}

	db := openTestDatabase(t, databasePath)
	defer db.Close()
	assertTableExists(t, db, "schema_migrations", false)
	assertTableExists(t, db, "certificates", false)
	assertLegacyDatabaseUnchanged(t, db, legacySchema)
}

func TestNewDatabaseDoesNotCreateMeaninglessBackup(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "db", "data.db")

	result, err := run(context.Background(), databasePath, registeredMigrations, fixedClock)
	if err != nil {
		t.Fatalf("initialize new database: %v", err)
	}
	if result.BackupPath != "" {
		t.Fatalf("new database created unexpected backup %q", result.BackupPath)
	}

	db := openTestDatabase(t, databasePath)
	defer db.Close()
	for _, tableName := range []string{
		"schema_migrations",
		"certificates",
		"totp_identities",
		"audit_logs",
		"ip_allocations",
		"vpn_users",
		"ip_allocation_reservations",
		"totp_reset_operations",
	} {
		assertTableExists(t, db, tableName, true)
	}
}

func TestTOTPIdentitySchemaDoesNotStoreSecrets(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "db", "data.db")
	if _, err := run(context.Background(), databasePath, registeredMigrations, fixedClock); err != nil {
		t.Fatalf("initialize database: %v", err)
	}

	db := openTestDatabase(t, databasePath)
	defer db.Close()
	rows, err := db.Query(`PRAGMA table_info(totp_identities)`)
	if err != nil {
		t.Fatalf("read totp_identities columns: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var columnID int
		var columnName, columnType string
		var notNull, primaryKey int
		var defaultValue sql.NullString
		if err := rows.Scan(
			&columnID,
			&columnName,
			&columnType,
			&notNull,
			&defaultValue,
			&primaryKey,
		); err != nil {
			t.Fatalf("scan totp_identities column: %v", err)
		}
		normalizedName := strings.ToLower(columnName)
		if strings.Contains(normalizedName, "secret") || strings.Contains(normalizedName, "seed") {
			t.Fatalf("sensitive column found in totp_identities: %s", columnName)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate totp_identities columns: %v", err)
	}
}

func fixedClock() time.Time {
	return time.Date(2026, time.July, 22, 10, 30, 0, 123456789, time.UTC)
}

func createLegacyDatabase(t *testing.T, databasePath string) map[string]string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(databasePath), 0o700); err != nil {
		t.Fatalf("create legacy database directory: %v", err)
	}
	db := openTestDatabase(t, databasePath)

	statements := []string{
		`CREATE TABLE user (id INTEGER PRIMARY KEY, login TEXT NOT NULL UNIQUE, marker TEXT NOT NULL)`,
		`CREATE TABLE settings (id INTEGER PRIMARY KEY, profile TEXT NOT NULL UNIQUE, marker TEXT NOT NULL)`,
		`CREATE TABLE o_v_config (id INTEGER PRIMARY KEY, profile TEXT NOT NULL UNIQUE, marker TEXT NOT NULL)`,
		`CREATE TABLE o_v_client_config (id INTEGER PRIMARY KEY, profile TEXT NOT NULL UNIQUE, marker TEXT NOT NULL)`,
		`CREATE TABLE easy_r_s_a_config (id INTEGER PRIMARY KEY, profile TEXT NOT NULL UNIQUE, marker TEXT NOT NULL)`,
		`INSERT INTO user (id, login, marker) VALUES (1, 'test-admin', 'preserve-user')`,
		`INSERT INTO settings (id, profile, marker) VALUES (1, 'default', 'preserve-settings')`,
		`INSERT INTO o_v_config (id, profile, marker) VALUES (1, 'default', 'preserve-server-config')`,
		`INSERT INTO o_v_client_config (id, profile, marker) VALUES (1, 'default', 'preserve-client-config')`,
		`INSERT INTO easy_r_s_a_config (id, profile, marker) VALUES (1, 'default', 'preserve-easyrsa-config')`,
	}
	for statementIndex, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			t.Fatalf("prepare legacy database statement %d: %v", statementIndex+1, err)
		}
	}

	schema := readLegacySchema(t, db)
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}
	return schema
}

func openTestDatabase(t *testing.T, databasePath string) *sql.DB {
	t.Helper()
	db, err := openSQLite(databasePath)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		t.Fatalf("connect to test database: %v", err)
	}
	return db
}

func readLegacySchema(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	schema := make(map[string]string, len(legacyTableNames))
	for _, tableName := range legacyTableNames {
		var createSQL string
		if err := db.QueryRow(
			`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`,
			tableName,
		).Scan(&createSQL); err != nil {
			t.Fatalf("read schema for %s: %v", tableName, err)
		}
		schema[tableName] = createSQL
	}
	return schema
}

func assertLegacyDatabaseUnchanged(t *testing.T, db *sql.DB, expectedSchema map[string]string) {
	t.Helper()
	actualSchema := readLegacySchema(t, db)
	if !reflect.DeepEqual(actualSchema, expectedSchema) {
		t.Fatalf("legacy table schema changed:\nactual: %#v\nexpected: %#v", actualSchema, expectedSchema)
	}

	expectedMarkers := map[string]string{
		"user":              "preserve-user",
		"settings":          "preserve-settings",
		"o_v_config":        "preserve-server-config",
		"o_v_client_config": "preserve-client-config",
		"easy_r_s_a_config": "preserve-easyrsa-config",
	}
	for tableName, expectedMarker := range expectedMarkers {
		var actualMarker string
		query := fmt.Sprintf(`SELECT marker FROM %q WHERE id = 1`, tableName)
		if err := db.QueryRow(query).Scan(&actualMarker); err != nil {
			t.Fatalf("read marker from %s: %v", tableName, err)
		}
		if actualMarker != expectedMarker {
			t.Fatalf("marker in %s = %q, want %q", tableName, actualMarker, expectedMarker)
		}
	}
}

func assertBackupIsValidPreMigrationDatabase(
	t *testing.T,
	backupPath string,
	expectedLegacySchema map[string]string,
) {
	t.Helper()
	backupDB := openTestDatabase(t, backupPath)
	defer backupDB.Close()

	var integrityResult string
	if err := backupDB.QueryRow(`PRAGMA integrity_check`).Scan(&integrityResult); err != nil {
		t.Fatalf("verify backup integrity: %v", err)
	}
	if integrityResult != "ok" {
		t.Fatalf("backup integrity result = %q, want ok", integrityResult)
	}
	assertLegacyDatabaseUnchanged(t, backupDB, expectedLegacySchema)
	assertTableExists(t, backupDB, "schema_migrations", false)
	assertTableExists(t, backupDB, "certificates", false)
}

func assertTableExists(t *testing.T, db *sql.DB, tableName string, expected bool) {
	t.Helper()
	var count int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`,
		tableName,
	).Scan(&count); err != nil {
		t.Fatalf("check table %s: %v", tableName, err)
	}
	if actual := count == 1; actual != expected {
		t.Fatalf("table %s existence = %t, want %t", tableName, actual, expected)
	}
}

func assertPathPermissions(t *testing.T, path string, expected os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if actual := info.Mode().Perm(); actual != expected {
		t.Fatalf("permissions for %s = %04o, want %04o", path, actual, expected)
	}
}
