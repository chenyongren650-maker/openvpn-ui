package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/d3vilh/openvpn-ui/migrations"
)

var lifecycleTestNow = time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)

type lifecycleCommandCall struct {
	Binary      string
	Args        []string
	WorkingDir  string
	Environment []string
}

type fakeLifecycleRunner struct {
	mu             sync.Mutex
	indexPath      string
	crlPath        string
	calls          []lifecycleCommandCall
	failNextRevoke int
	failNextCRL    int
	renewal        func() error
}

func (r *fakeLifecycleRunner) Run(
	_ context.Context,
	binary string,
	args []string,
	workingDir string,
	environment []string,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.calls = append(r.calls, lifecycleCommandCall{
		Binary:      binary,
		Args:        append([]string(nil), args...),
		WorkingDir:  workingDir,
		Environment: append([]string(nil), environment...),
	})
	if len(args) >= 2 && args[len(args)-2] == "renew" {
		if r.renewal == nil {
			return errors.New("synthetic renewal handler is unavailable")
		}
		return r.renewal()
	}
	command := args[len(args)-1]
	if len(args) >= 2 &&
		(args[len(args)-2] == "revoke" ||
			args[len(args)-2] == "revoke-renewed") {
		if r.failNextRevoke > 0 {
			r.failNextRevoke--
			return ErrCertificateCommand
		}
		data, err := os.ReadFile(r.indexPath)
		if err != nil {
			return err
		}
		lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
		targetIndex := len(lines) - 1
		if args[len(args)-2] == "revoke-renewed" {
			targetIndex = 0
		}
		fields := strings.Split(lines[targetIndex], "\t")
		if len(fields) != 6 {
			return errors.New("synthetic PKI index is malformed")
		}
		fields[0] = "R"
		fields[2] = "260723120000Z"
		lines[targetIndex] = strings.Join(fields, "\t")
		return os.WriteFile(
			r.indexPath,
			[]byte(strings.Join(lines, "\n")+"\n"),
			0o600,
		)
	}
	if command == "gen-crl" {
		if r.failNextCRL > 0 {
			r.failNextCRL--
			return ErrCertificateCRL
		}
		return os.WriteFile(r.crlPath, []byte("synthetic-crl-after-revoke\n"), 0o600)
	}
	return fmt.Errorf("unexpected synthetic Easy-RSA command: %v", args)
}

func (r *fakeLifecycleRunner) renewalCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, call := range r.calls {
		if len(call.Args) >= 2 && call.Args[len(call.Args)-2] == "renew" {
			count++
		}
	}
	return count
}

func (r *fakeLifecycleRunner) commandCounts() (revoke int, genCRL int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, call := range r.calls {
		if call.Args[len(call.Args)-1] == "gen-crl" {
			genCRL++
		}
		if len(call.Args) >= 2 &&
			(call.Args[len(call.Args)-2] == "revoke" ||
				call.Args[len(call.Args)-2] == "revoke-renewed") {
			revoke++
		}
	}
	return revoke, genCRL
}

type fakeLifecycleDisconnector struct {
	mu        sync.Mutex
	calls     int
	connected bool
	err       error
}

func (d *fakeLifecycleDisconnector) Disconnect(
	_ context.Context,
	_ string,
) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	return d.connected, d.err
}

func (d *fakeLifecycleDisconnector) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func TestArchiveCertificateIsIdempotentAndDoesNotChangePKI(t *testing.T) {
	service, db, pkiDir, runner, disconnector := newLifecycleTestService(
		t,
		"revoked",
		"test-client",
		"A1",
		"10.250.71.10",
	)
	defer db.Close()
	before := snapshotTestPKI(t, pkiDir)

	first, err := service.ArchiveCertificate(
		context.Background(),
		1,
		adminLifecycleActor(),
	)
	if err != nil || first.AlreadyArchived {
		t.Fatalf("first archive result = %+v, error = %v", first, err)
	}
	second, err := service.ArchiveCertificate(
		context.Background(),
		1,
		adminLifecycleActor(),
	)
	if err != nil || !second.AlreadyArchived {
		t.Fatalf("second archive result = %+v, error = %v", second, err)
	}

	after := snapshotTestPKI(t, pkiDir)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("archive changed the isolated PKI")
	}
	if revoke, genCRL := runner.commandCounts(); revoke != 0 || genCRL != 0 {
		t.Fatalf("archive executed Easy-RSA commands: revoke=%d gen-crl=%d", revoke, genCRL)
	}
	if disconnector.callCount() != 0 {
		t.Fatal("archive attempted to disconnect an OpenVPN session")
	}

	var status string
	var archivedAt sql.NullTime
	if err := db.QueryRow(`SELECT status, archived_at FROM certificates WHERE id = 1`).
		Scan(&status, &archivedAt); err != nil {
		t.Fatalf("read archived certificate: %v", err)
	}
	if status != "archived" || !archivedAt.Valid {
		t.Fatalf("archived state = %q, archived_at valid = %t", status, archivedAt.Valid)
	}
	assertLifecycleAuditResults(
		t,
		db,
		auditActionArchive,
		[]string{"success", "already_archived"},
	)
}

func TestArchiveCertificateRequiresAdministratorPermission(t *testing.T) {
	service, db, pkiDir, runner, _ := newLifecycleTestService(
		t,
		"revoked",
		"test-client",
		"A1",
		"",
	)
	defer db.Close()
	before := snapshotTestPKI(t, pkiDir)

	_, err := service.ArchiveCertificate(
		context.Background(),
		1,
		CertificateLifecycleActor{
			UserID:    2,
			SourceIP:  "192.0.2.20",
			RequestID: "request-non-admin",
		},
	)
	if !errors.Is(err, ErrCertificateForbidden) {
		t.Fatalf("archive permission error = %v", err)
	}
	if !reflect.DeepEqual(before, snapshotTestPKI(t, pkiDir)) {
		t.Fatal("denied archive changed the isolated PKI")
	}
	if revoke, genCRL := runner.commandCounts(); revoke != 0 || genCRL != 0 {
		t.Fatal("denied archive executed Easy-RSA")
	}

	var status string
	if err := db.QueryRow(`SELECT status FROM certificates WHERE id = 1`).Scan(&status); err != nil {
		t.Fatalf("read certificate after denied archive: %v", err)
	}
	if status != "revoked" {
		t.Fatalf("certificate status after denied archive = %q", status)
	}
	assertLifecycleAuditResults(t, db, auditActionArchive, []string{"failed"})
	assertLatestAuditError(t, db, "permission_denied")
}

func TestRevokeCertificateIsIdempotentAndMarksStaticIPPendingRelease(t *testing.T) {
	service, db, pkiDir, runner, disconnector := newLifecycleTestService(
		t,
		"valid",
		"test-client",
		"A1",
		"10.250.71.10",
	)
	defer db.Close()
	disconnector.connected = true

	first, err := service.RevokeCertificate(
		context.Background(),
		1,
		"test-client",
		adminLifecycleActor(),
	)
	if err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if first.AlreadyRevoked || !first.Disconnected || first.DisconnectFailed {
		t.Fatalf("unexpected first revoke result: %+v", first)
	}
	crlInfo, err := os.Stat(filepath.Join(pkiDir, "crl.pem"))
	if err != nil {
		t.Fatalf("stat generated CRL: %v", err)
	}
	if permissions := crlInfo.Mode().Perm(); permissions != 0o644 {
		t.Fatalf("generated CRL permissions = %04o, want 0644", permissions)
	}
	second, err := service.RevokeCertificate(
		context.Background(),
		1,
		"test-client",
		adminLifecycleActor(),
	)
	if err != nil || !second.AlreadyRevoked {
		t.Fatalf("second revoke result = %+v, error = %v", second, err)
	}

	revoke, genCRL := runner.commandCounts()
	if revoke != 1 || genCRL != 1 {
		t.Fatalf("Easy-RSA command counts = revoke %d, gen-crl %d; want 1 and 1", revoke, genCRL)
	}
	if disconnector.callCount() != 1 {
		t.Fatalf("disconnect calls = %d, want 1", disconnector.callCount())
	}
	assertRunnerUsesArgumentArrays(t, runner)

	var certificateStatus, allocationStatus, ipAddress string
	if err := db.QueryRow(`SELECT status FROM certificates WHERE id = 1`).
		Scan(&certificateStatus); err != nil {
		t.Fatalf("read revoked certificate: %v", err)
	}
	if err := db.QueryRow(`SELECT status, ip_address
		FROM ip_allocations WHERE certificate_id = 1`).
		Scan(&allocationStatus, &ipAddress); err != nil {
		t.Fatalf("read pending-release allocation: %v", err)
	}
	if certificateStatus != "revoked" || allocationStatus != "pending_release" ||
		ipAddress != "10.250.71.10" {
		t.Fatalf(
			"certificate status=%q, allocation status=%q, ip=%q",
			certificateStatus,
			allocationStatus,
			ipAddress,
		)
	}
	assertLifecycleAuditResults(
		t,
		db,
		auditActionRevoke,
		[]string{CertificateAuditResultStarted, "success", "already_revoked"},
	)
}

func TestRevokeCertificateRequiresAdministratorPermission(t *testing.T) {
	service, db, pkiDir, runner, disconnector := newLifecycleTestService(
		t,
		"valid",
		"test-client",
		"A1",
		"",
	)
	defer db.Close()
	before := snapshotTestPKI(t, pkiDir)

	_, err := service.RevokeCertificate(
		context.Background(),
		1,
		"test-client",
		CertificateLifecycleActor{
			UserID:    2,
			SourceIP:  "192.0.2.20",
			RequestID: "request-non-admin-revoke",
		},
	)
	if !errors.Is(err, ErrCertificateForbidden) {
		t.Fatalf("revoke permission error = %v", err)
	}
	if !reflect.DeepEqual(before, snapshotTestPKI(t, pkiDir)) {
		t.Fatal("denied revoke changed the isolated PKI")
	}
	if revoke, genCRL := runner.commandCounts(); revoke != 0 || genCRL != 0 {
		t.Fatalf("denied revoke executed Easy-RSA: revoke=%d gen-crl=%d", revoke, genCRL)
	}
	if disconnector.callCount() != 0 {
		t.Fatal("denied revoke attempted to disconnect a session")
	}
	assertLifecycleAuditResults(t, db, auditActionRevoke, []string{"failed"})
	assertLatestAuditError(t, db, "permission_denied")
}

func TestRevokeCertificateStopsWhenAuditIsUnavailable(t *testing.T) {
	service, db, pkiDir, runner, disconnector := newLifecycleTestService(
		t,
		"valid",
		"revoke-audit-client",
		"A1",
		"",
	)
	defer db.Close()
	before := snapshotTestPKI(t, pkiDir)
	if _, err := db.Exec(`CREATE TRIGGER reject_revoke_audit
		BEFORE INSERT ON audit_logs
		WHEN NEW.action = 'certificate.revoke'
		BEGIN
			SELECT RAISE(ABORT, 'forced revoke audit failure');
		END`); err != nil {
		t.Fatalf("create revoke audit failure trigger: %v", err)
	}

	_, err := service.RevokeCertificate(
		context.Background(),
		1,
		"revoke-audit-client",
		adminLifecycleActor(),
	)
	if err == nil {
		t.Fatal("revoke continued while the mandatory audit log was unavailable")
	}
	if revoke, genCRL := runner.commandCounts(); revoke != 0 || genCRL != 0 {
		t.Fatalf(
			"revoke executed Easy-RSA before audit: revoke=%d gen-crl=%d",
			revoke,
			genCRL,
		)
	}
	if disconnector.callCount() != 0 {
		t.Fatal("revoke disconnected a session before the audit record existed")
	}
	if !reflect.DeepEqual(before, snapshotTestPKI(t, pkiDir)) {
		t.Fatal("revoke changed the isolated PKI before the audit record existed")
	}
}

func TestConcurrentRevokeExecutesEasyRSAOnce(t *testing.T) {
	service, db, _, runner, disconnector := newLifecycleTestService(
		t,
		"valid",
		"test-client",
		"A1",
		"",
	)
	defer db.Close()

	const requests = 12
	start := make(chan struct{})
	results := make(chan error, requests)
	var wait sync.WaitGroup
	for index := 0; index < requests; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := service.RevokeCertificate(
				context.Background(),
				1,
				"test-client",
				adminLifecycleActor(),
			)
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent revoke returned error: %v", err)
		}
	}

	revoke, genCRL := runner.commandCounts()
	if revoke != 1 || genCRL != 1 || disconnector.callCount() != 1 {
		t.Fatalf(
			"concurrent side effects: revoke=%d gen-crl=%d disconnect=%d",
			revoke,
			genCRL,
			disconnector.callCount(),
		)
	}
	var auditCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_logs
		WHERE action = ?`, auditActionRevoke).Scan(&auditCount); err != nil {
		t.Fatalf("count concurrent revoke audits: %v", err)
	}
	if auditCount != requests+1 {
		t.Fatalf("concurrent revoke audit count = %d, want %d", auditCount, requests+1)
	}
}

func TestRevokeRetriesAfterCRLFailureWithoutRepeatingRevoke(t *testing.T) {
	service, db, _, runner, _ := newLifecycleTestService(
		t,
		"valid",
		"test-client",
		"A1",
		"",
	)
	defer db.Close()
	runner.failNextCRL = 1

	_, err := service.RevokeCertificate(
		context.Background(),
		1,
		"test-client",
		adminLifecycleActor(),
	)
	if !errors.Is(err, ErrCertificateCRL) {
		t.Fatalf("first revoke error = %v, want CRL failure", err)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM certificates WHERE id = 1`).Scan(&status); err != nil {
		t.Fatalf("read status after CRL failure: %v", err)
	}
	if status != "valid" {
		t.Fatalf("database status after CRL failure = %q, want valid", status)
	}
	if _, err := service.DownloadableCertificate(context.Background(), 1); !errors.Is(err, ErrCertificateDownloadBlocked) {
		t.Fatalf("partially revoked certificate download error = %v", err)
	}

	if _, err := service.RevokeCertificate(
		context.Background(),
		1,
		"test-client",
		adminLifecycleActor(),
	); err != nil {
		t.Fatalf("retry revoke: %v", err)
	}
	revoke, genCRL := runner.commandCounts()
	if revoke != 1 || genCRL != 2 {
		t.Fatalf("retry command counts = revoke %d, gen-crl %d; want 1 and 2", revoke, genCRL)
	}
	assertLifecycleAuditResults(
		t,
		db,
		auditActionRevoke,
		[]string{
			CertificateAuditResultStarted,
			"failed",
			CertificateAuditResultStarted,
			"success",
		},
	)
}

func TestRevokeRetriesAfterDatabaseFailureWithoutRepeatingRevoke(t *testing.T) {
	service, db, _, runner, _ := newLifecycleTestService(
		t,
		"valid",
		"test-client",
		"A1",
		"",
	)
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER reject_revoked_status
		BEFORE UPDATE OF status ON certificates
		WHEN NEW.status = 'revoked'
		BEGIN
			SELECT RAISE(ABORT, 'forced lifecycle database failure');
		END`); err != nil {
		t.Fatalf("create lifecycle failure trigger: %v", err)
	}

	if _, err := service.RevokeCertificate(
		context.Background(),
		1,
		"test-client",
		adminLifecycleActor(),
	); err == nil {
		t.Fatal("expected forced lifecycle database failure")
	}
	if _, err := db.Exec(`DROP TRIGGER reject_revoked_status`); err != nil {
		t.Fatalf("drop lifecycle failure trigger: %v", err)
	}
	if _, err := service.RevokeCertificate(
		context.Background(),
		1,
		"test-client",
		adminLifecycleActor(),
	); err != nil {
		t.Fatalf("retry after database failure: %v", err)
	}

	revoke, genCRL := runner.commandCounts()
	if revoke != 1 || genCRL != 2 {
		t.Fatalf(
			"database retry command counts = revoke %d, gen-crl %d; want 1 and 2",
			revoke,
			genCRL,
		)
	}
}

func TestRevokeValidatesConfirmationIdentityAndPKI(t *testing.T) {
	tests := []struct {
		name           string
		databaseCN     string
		databaseSerial string
		indexCN        string
		indexSerial    string
		confirmation   string
		wantError      error
	}{
		{
			name:           "confirmation mismatch",
			databaseCN:     "test-client",
			databaseSerial: "A1",
			indexCN:        "test-client",
			indexSerial:    "A1",
			confirmation:   "other-client",
			wantError:      ErrCertificateConfirmation,
		},
		{
			name:           "command injection common name",
			databaseCN:     "test-client;touch",
			databaseSerial: "A1",
			indexCN:        "test-client;touch",
			indexSerial:    "A1",
			confirmation:   "test-client;touch",
			wantError:      ErrCertificateIdentity,
		},
		{
			name:           "path traversal common name",
			databaseCN:     "../test-client",
			databaseSerial: "A1",
			indexCN:        "../test-client",
			indexSerial:    "A1",
			confirmation:   "../test-client",
			wantError:      ErrCertificateIdentity,
		},
		{
			name:           "invalid serial",
			databaseCN:     "test-client",
			databaseSerial: "A1;id",
			indexCN:        "test-client",
			indexSerial:    "A1",
			confirmation:   "test-client",
			wantError:      ErrCertificateIdentity,
		},
		{
			name:           "protected server certificate",
			databaseCN:     "protected-server",
			databaseSerial: "A1",
			indexCN:        "protected-server",
			indexSerial:    "A1",
			confirmation:   "protected-server",
			wantError:      ErrCertificateIdentity,
		},
		{
			name:           "PKI common name mismatch",
			databaseCN:     "test-client",
			databaseSerial: "A1",
			indexCN:        "other-client",
			indexSerial:    "A1",
			confirmation:   "test-client",
			wantError:      ErrCertificatePKIMismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, db, _, runner, _ := newLifecycleTestService(
				t,
				"valid",
				test.indexCN,
				test.indexSerial,
				"",
			)
			defer db.Close()
			if _, err := db.Exec(`UPDATE certificates
				SET common_name = ?, serial_number = ? WHERE id = 1`,
				test.databaseCN,
				test.databaseSerial,
			); err != nil {
				t.Fatalf("prepare database identity: %v", err)
			}

			_, err := service.RevokeCertificate(
				context.Background(),
				1,
				test.confirmation,
				adminLifecycleActor(),
			)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("revoke error = %v, want %v", err, test.wantError)
			}
			if revoke, genCRL := runner.commandCounts(); revoke != 0 || genCRL != 0 {
				t.Fatalf("invalid identity executed Easy-RSA: revoke=%d gen-crl=%d", revoke, genCRL)
			}
		})
	}
}

func TestDownloadableCertificateBlocksUnsafeLifecycleStates(t *testing.T) {
	service, db, _, _, _ := newLifecycleTestService(
		t,
		"valid",
		"test-client",
		"A1",
		"",
	)
	defer db.Close()

	state, err := service.DownloadableCertificate(context.Background(), 1)
	if err != nil || state.CommonName != "test-client" {
		t.Fatalf("valid downloadable certificate = %+v, error = %v", state, err)
	}
	for _, status := range []string{"revoked", "expired", "archived"} {
		archivedAt := any(nil)
		if status == "archived" {
			archivedAt = lifecycleTestNow
		}
		if _, err := db.Exec(`UPDATE certificates
			SET status = ?, archived_at = ? WHERE id = 1`, status, archivedAt); err != nil {
			t.Fatalf("set certificate status %s: %v", status, err)
		}
		if _, err := service.DownloadableCertificate(context.Background(), 1); !errors.Is(err, ErrCertificateDownloadBlocked) {
			t.Fatalf("download status %s error = %v", status, err)
		}
	}

	if _, err := db.Exec(`UPDATE certificates
		SET common_name = '../unsafe', status = 'valid', archived_at = NULL
		WHERE id = 1`); err != nil {
		t.Fatalf("set unsafe common name: %v", err)
	}
	if _, err := service.DownloadableCertificate(context.Background(), 1); !errors.Is(err, ErrCertificateIdentity) {
		t.Fatalf("unsafe path download error = %v", err)
	}
}

func TestRenewCertificateSyncsMetadataAndIsIdempotent(t *testing.T) {
	service, db, pkiDir, runner, _ := newLifecycleTestService(
		t,
		"valid",
		"renew-test-client",
		"A1",
		"10.250.71.10",
	)
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO ip_allocations (
		ip_address, pool_name, certificate_id, status, allocated_at
	) VALUES ('10.250.71.10', 'restricted', 1, 'allocated', ?)`,
		lifecycleTestNow,
	); err != nil {
		t.Fatalf("seed renewal static IP allocation: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO totp_identities (
		certificate_id, tfa_name, issuer, status, created_at
	) VALUES (1, 'user@example.invalid', 'ZHISUAN', 'active', ?)`,
		lifecycleTestNow,
	); err != nil {
		t.Fatalf("seed renewal TOTP identity metadata: %v", err)
	}

	runner.renewal = func() error {
		prepareSyntheticRenewal(
			t,
			pkiDir,
			"renew-test-client",
			"A1",
			"B2",
		)
		return nil
	}
	result, err := service.RenewCertificate(
		context.Background(),
		1,
		adminLifecycleActor(),
	)
	if err != nil {
		t.Fatalf("renew certificate: %v", err)
	}
	if result.AlreadyRenewed ||
		result.NewCertificateID == 0 ||
		result.CommonName != "renew-test-client" ||
		runner.renewalCount() != 1 {
		t.Fatalf(
			"unexpected renewal result: %+v, calls=%d",
			result,
			runner.renewalCount(),
		)
	}
	runner.mu.Lock()
	renewalCall := runner.calls[0]
	runner.mu.Unlock()
	if renewalCall.Binary == "/bin/bash" ||
		renewalCall.Binary == "/bin/sh" ||
		!reflect.DeepEqual(
			renewalCall.Args[len(renewalCall.Args)-2:],
			[]string{"renew", "renew-test-client"},
		) {
		t.Fatalf("renewal did not use a direct Easy-RSA argument array: %+v", renewalCall)
	}

	var newStatus, newStaticIP string
	if err := db.QueryRow(
		`SELECT status, static_ip FROM certificates WHERE id = ?`,
		result.NewCertificateID,
	).Scan(&newStatus, &newStaticIP); err != nil {
		t.Fatalf("read synchronized renewed certificate: %v", err)
	}
	if newStatus != "valid" || newStaticIP != "10.250.71.10" {
		t.Fatalf(
			"renewed database status=%q static_ip=%q",
			newStatus,
			newStaticIP,
		)
	}
	var totpCertificateID int64
	if err := db.QueryRow(`SELECT certificate_id FROM totp_identities
		WHERE tfa_name = 'user@example.invalid'`).Scan(&totpCertificateID); err != nil {
		t.Fatalf("read transferred TOTP identity metadata: %v", err)
	}
	if totpCertificateID != result.NewCertificateID {
		t.Fatalf(
			"renewed TOTP identity certificate=%d, want %d",
			totpCertificateID,
			result.NewCertificateID,
		)
	}
	var allocationCertificateID int64
	var allocationStatus string
	if err := db.QueryRow(`SELECT certificate_id, status FROM ip_allocations
		WHERE ip_address = '10.250.71.10'`).Scan(
		&allocationCertificateID,
		&allocationStatus,
	); err != nil {
		t.Fatalf("read transferred renewal allocation: %v", err)
	}
	if allocationCertificateID != result.NewCertificateID ||
		allocationStatus != "allocated" {
		t.Fatalf(
			"renewal allocation certificate=%d status=%q",
			allocationCertificateID,
			allocationStatus,
		)
	}
	if _, err := service.DownloadableCertificate(
		context.Background(),
		1,
	); !errors.Is(err, ErrCertificateDownloadBlocked) {
		t.Fatalf("historical certificate download error = %v", err)
	}
	if state, err := service.DownloadableCertificate(
		context.Background(),
		result.NewCertificateID,
	); err != nil || state.SerialNumber != "B2" {
		t.Fatalf("renewed certificate download state = %+v, error = %v", state, err)
	}

	retry, err := service.RenewCertificate(
		context.Background(),
		1,
		adminLifecycleActor(),
	)
	if err != nil || !retry.AlreadyRenewed ||
		retry.NewCertificateID != result.NewCertificateID ||
		runner.renewalCount() != 1 {
		t.Fatalf(
			"idempotent renewal retry = %+v, error=%v, calls=%d",
			retry,
			err,
			runner.renewalCount(),
		)
	}

	if _, err := service.RevokeCertificate(
		context.Background(),
		1,
		"renew-test-client",
		adminLifecycleActor(),
	); err != nil {
		t.Fatalf("revoke historical renewed certificate: %v", err)
	}
	if err := db.QueryRow(`SELECT certificate_id, status FROM ip_allocations
		WHERE ip_address = '10.250.71.10'`).Scan(
		&allocationCertificateID,
		&allocationStatus,
	); err != nil {
		t.Fatalf("read allocation after historical revoke: %v", err)
	}
	if allocationCertificateID != result.NewCertificateID ||
		allocationStatus != "allocated" {
		t.Fatalf(
			"historical revoke changed active successor allocation: certificate=%d status=%q",
			allocationCertificateID,
			allocationStatus,
		)
	}
	assertLifecycleAuditResults(
		t,
		db,
		CertificateAuditActionRenew,
		[]string{CertificateAuditResultStarted, "success", "already_renewed"},
	)
}

func TestRenewCertificateRequiresAdministratorPermission(t *testing.T) {
	service, db, pkiDir, runner, _ := newLifecycleTestService(
		t,
		"valid",
		"renew-permission-client",
		"A1",
		"",
	)
	defer db.Close()
	before := snapshotTestPKI(t, pkiDir)
	executorCalled := false
	runner.renewal = func() error {
		executorCalled = true
		return nil
	}
	_, err := service.RenewCertificate(
		context.Background(),
		1,
		CertificateLifecycleActor{
			UserID:    2,
			SourceIP:  "192.0.2.20",
			RequestID: "request-renew-non-admin",
		},
	)
	if !errors.Is(err, ErrCertificateForbidden) {
		t.Fatalf("renew permission error = %v", err)
	}
	if executorCalled {
		t.Fatal("denied renewal executed the renewal command")
	}
	if !reflect.DeepEqual(before, snapshotTestPKI(t, pkiDir)) {
		t.Fatal("denied renewal changed the isolated PKI")
	}
	assertLifecycleAuditResults(
		t,
		db,
		CertificateAuditActionRenew,
		[]string{"failed"},
	)
	assertLatestAuditError(t, db, "permission_denied")
}

func TestRenewCertificateStopsWhenAuditIsUnavailable(t *testing.T) {
	service, db, pkiDir, runner, _ := newLifecycleTestService(
		t,
		"valid",
		"renew-audit-client",
		"A1",
		"",
	)
	defer db.Close()
	before := snapshotTestPKI(t, pkiDir)
	if _, err := db.Exec(`CREATE TRIGGER reject_renew_audit
		BEFORE INSERT ON audit_logs
		WHEN NEW.action = 'certificate.renew'
		BEGIN
			SELECT RAISE(ABORT, 'forced renewal audit failure');
		END`); err != nil {
		t.Fatalf("create renewal audit failure trigger: %v", err)
	}
	runner.renewal = func() error {
		t.Fatal("renewal command ran before the audit record existed")
		return nil
	}

	_, err := service.RenewCertificate(
		context.Background(),
		1,
		adminLifecycleActor(),
	)
	if err == nil {
		t.Fatal("renewal continued while the mandatory audit log was unavailable")
	}
	if runner.renewalCount() != 0 {
		t.Fatalf(
			"renewal command calls before audit = %d, want 0",
			runner.renewalCount(),
		)
	}
	if !reflect.DeepEqual(before, snapshotTestPKI(t, pkiDir)) {
		t.Fatal("renewal changed the isolated PKI before the audit record existed")
	}
}

func TestRenewCertificateRetryCompensatesMetadataSyncFailure(t *testing.T) {
	service, db, pkiDir, runner, _ := newLifecycleTestService(
		t,
		"valid",
		"renew-retry-client",
		"A1",
		"",
	)
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER reject_renewed_serial
		BEFORE INSERT ON certificates
		WHEN NEW.serial_number = 'B2'
		BEGIN
			SELECT RAISE(ABORT, 'forced renewal metadata failure');
		END`); err != nil {
		t.Fatalf("create renewal metadata failure trigger: %v", err)
	}

	runner.renewal = func() error {
		prepareSyntheticRenewal(
			t,
			pkiDir,
			"renew-retry-client",
			"A1",
			"B2",
		)
		return nil
	}
	_, err := service.RenewCertificate(
		context.Background(),
		1,
		adminLifecycleActor(),
	)
	if !errors.Is(err, ErrCertificateRenewal) {
		t.Fatalf("renewal metadata failure error = %v", err)
	}
	if _, err := db.Exec(`DROP TRIGGER reject_renewed_serial`); err != nil {
		t.Fatalf("drop renewal metadata failure trigger: %v", err)
	}

	retry, err := service.RenewCertificate(
		context.Background(),
		1,
		adminLifecycleActor(),
	)
	if err != nil || !retry.AlreadyRenewed || retry.NewCertificateID == 0 {
		t.Fatalf("renewal compensation retry = %+v, error = %v", retry, err)
	}
	if runner.renewalCount() != 1 {
		t.Fatalf("renewal command calls = %d, want 1", runner.renewalCount())
	}
	assertLifecycleAuditResults(
		t,
		db,
		CertificateAuditActionRenew,
		[]string{CertificateAuditResultStarted, "failed", "already_renewed"},
	)
}

func TestHistoricalRenewedCertificateUsesRevokeRenewed(t *testing.T) {
	service, db, pkiDir, _, _ := newLifecycleTestService(
		t,
		"valid",
		"renewed-history-client",
		"A1",
		"",
	)
	defer db.Close()
	prepareSyntheticRenewal(
		t,
		pkiDir,
		"renewed-history-client",
		"A1",
		"B2",
	)

	state, err := service.loadCertificate(context.Background(), 1)
	if err != nil {
		t.Fatalf("load historical certificate state: %v", err)
	}
	command, err := service.resolveRevokeCommand(state)
	if err != nil {
		t.Fatalf("resolve historical revoke command: %v", err)
	}
	if command != "revoke-renewed" {
		t.Fatalf("historical revoke command = %q, want revoke-renewed", command)
	}
	if _, err := service.DownloadableCertificate(
		context.Background(),
		1,
	); !errors.Is(err, ErrCertificateDownloadBlocked) {
		t.Fatalf("historical download error = %v", err)
	}
}

func TestPerformCertificateDownloadRequiresAdministratorPermission(t *testing.T) {
	service, db, _, _, _ := newLifecycleTestService(
		t,
		"valid",
		"download-permission-client",
		"A1",
		"",
	)
	defer db.Close()

	executorCalled := false
	err := service.PerformCertificateDownload(
		context.Background(),
		1,
		CertificateLifecycleActor{
			UserID:    2,
			SourceIP:  "192.0.2.20",
			RequestID: "request-download-non-admin",
		},
		func(CertificateState) error {
			executorCalled = true
			return nil
		},
	)
	if !errors.Is(err, ErrCertificateForbidden) {
		t.Fatalf("download permission error = %v", err)
	}
	if executorCalled {
		t.Fatal("denied download executed the configuration delivery")
	}
	assertLifecycleAuditResults(
		t,
		db,
		auditActionDownload,
		[]string{"failed"},
	)
	assertLatestAuditError(t, db, "permission_denied")
}

func TestPerformCertificateDownloadStopsWhenAuditIsUnavailable(t *testing.T) {
	service, db, _, _, _ := newLifecycleTestService(
		t,
		"valid",
		"download-audit-client",
		"A1",
		"",
	)
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER reject_download_audit
		BEFORE INSERT ON audit_logs
		WHEN NEW.action = 'certificate.download'
		BEGIN
			SELECT RAISE(ABORT, 'forced download audit failure');
		END`); err != nil {
		t.Fatalf("create download audit failure trigger: %v", err)
	}

	executorCalled := false
	err := service.PerformCertificateDownload(
		context.Background(),
		1,
		adminLifecycleActor(),
		func(CertificateState) error {
			executorCalled = true
			return nil
		},
	)
	if err == nil {
		t.Fatal("download continued while the mandatory audit log was unavailable")
	}
	if executorCalled {
		t.Fatal("download delivered configuration before the audit record existed")
	}
}

func TestDownloadDeliverySerializesConcurrentRevoke(t *testing.T) {
	service, db, _, runner, _ := newLifecycleTestService(
		t,
		"valid",
		"concurrent-download-client",
		"A1",
		"",
	)
	defer db.Close()

	downloadStarted := make(chan struct{})
	releaseDownload := make(chan struct{})
	downloadDone := make(chan error, 1)
	go func() {
		downloadDone <- service.PerformCertificateDownload(
			context.Background(),
			1,
			adminLifecycleActor(),
			func(CertificateState) error {
				close(downloadStarted)
				<-releaseDownload
				return nil
			},
		)
	}()
	<-downloadStarted

	revokeDone := make(chan error, 1)
	go func() {
		_, err := service.RevokeCertificate(
			context.Background(),
			1,
			"concurrent-download-client",
			adminLifecycleActor(),
		)
		revokeDone <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if revoke, _ := runner.commandCounts(); revoke != 0 {
		t.Fatal("concurrent revoke began before download delivery completed")
	}

	close(releaseDownload)
	if err := <-downloadDone; err != nil {
		t.Fatalf("perform certificate download: %v", err)
	}
	if err := <-revokeDone; err != nil {
		t.Fatalf("revoke after certificate download: %v", err)
	}
	if revoke, _ := runner.commandCounts(); revoke != 1 {
		t.Fatalf("revoke command count = %d, want 1", revoke)
	}
	assertLifecycleAuditResults(
		t,
		db,
		auditActionDownload,
		[]string{CertificateAuditResultStarted, "success"},
	)
}

func TestManagementDisconnectHonorsTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for stalled management server: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()
	disconnector := managementLifecycleDisconnector{
		network: "tcp",
		address: listener.Addr().String(),
		timeout: 50 * time.Millisecond,
	}
	start := time.Now()
	if _, err := disconnector.Disconnect(
		context.Background(),
		"timeout-test-client",
	); err == nil {
		t.Fatal("stalled management connection did not time out")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("management timeout took %s, want under one second", elapsed)
	}
	select {
	case connection := <-accepted:
		connection.Close()
	default:
	}
}

func TestRevokeDisconnectFailureIsAuditedAsWarning(t *testing.T) {
	service, db, _, _, disconnector := newLifecycleTestService(
		t,
		"valid",
		"test-client",
		"A1",
		"",
	)
	defer db.Close()
	disconnector.err = errors.New("synthetic management interface failure")

	result, err := service.RevokeCertificate(
		context.Background(),
		1,
		"test-client",
		adminLifecycleActor(),
	)
	if err != nil {
		t.Fatalf("revoke with disconnect warning: %v", err)
	}
	if !result.DisconnectFailed {
		t.Fatalf("disconnect warning result = %+v", result)
	}
	assertLifecycleAuditResults(
		t,
		db,
		auditActionRevoke,
		[]string{CertificateAuditResultStarted, "success_with_warning"},
	)
	assertLatestAuditError(t, db, "disconnect_failed")
}

func TestLifecycleAuditContainsRequiredRequestMetadata(t *testing.T) {
	service, db, _, _, _ := newLifecycleTestService(
		t,
		"valid",
		"test-client",
		"A1",
		"",
	)
	defer db.Close()
	actor := adminLifecycleActor()
	if err := service.RecordCertificateDownloadAudit(
		context.Background(),
		1,
		actor,
		"success",
		"",
	); err != nil {
		t.Fatalf("write certificate download audit: %v", err)
	}

	var (
		actorUserID                              int64
		sourceIP, action, targetType, targetID   string
		summary, result, errorSummary, requestID string
	)
	if err := db.QueryRow(`SELECT
		actor_user_id, source_ip, action, target_type, target_id,
		summary, result, error_summary, request_id
	FROM audit_logs ORDER BY id DESC LIMIT 1`).Scan(
		&actorUserID,
		&sourceIP,
		&action,
		&targetType,
		&targetID,
		&summary,
		&result,
		&errorSummary,
		&requestID,
	); err != nil {
		t.Fatalf("read certificate download audit: %v", err)
	}
	if actorUserID != actor.UserID || sourceIP != actor.SourceIP ||
		action != auditActionDownload || targetType != auditTargetType ||
		targetID != "1" || summary == "" || result != "success" ||
		errorSummary != "" || requestID != actor.RequestID {
		t.Fatalf("incomplete lifecycle audit metadata")
	}
	for _, forbidden := range []string{"password", "secret", "private key", ".ovpn"} {
		if strings.Contains(strings.ToLower(summary+" "+errorSummary), forbidden) {
			t.Fatalf("audit contains prohibited content marker %q", forbidden)
		}
	}
}

func TestAdministrativeAuditNormalizesUntrustedTarget(t *testing.T) {
	service, db, _, _, _ := newLifecycleTestService(
		t,
		"valid",
		"audit-test-client",
		"A1",
		"",
	)
	defer db.Close()
	if err := service.RecordCertificateOperationAudit(
		context.Background(),
		adminLifecycleActor(),
		CertificateAuditActionCreate,
		"../../unsafe target",
		"failed",
		"invalid_input",
	); err != nil {
		t.Fatalf("write administrative certificate audit: %v", err)
	}
	var action, targetID, result, errorSummary string
	if err := db.QueryRow(`SELECT action, target_id, result, error_summary
		FROM audit_logs ORDER BY id DESC LIMIT 1`).Scan(
		&action,
		&targetID,
		&result,
		&errorSummary,
	); err != nil {
		t.Fatalf("read administrative certificate audit: %v", err)
	}
	if action != CertificateAuditActionCreate ||
		targetID != "unavailable" ||
		result != "failed" ||
		errorSummary != "invalid_input" {
		t.Fatalf(
			"administrative audit = action %q target %q result %q error %q",
			action,
			targetID,
			result,
			errorSummary,
		)
	}
}

func newLifecycleTestService(
	t *testing.T,
	status string,
	commonName string,
	serialNumber string,
	staticIP string,
) (
	*CertificateLifecycleService,
	*sql.DB,
	string,
	*fakeLifecycleRunner,
	*fakeLifecycleDisconnector,
) {
	t.Helper()
	root := t.TempDir()
	easyRSAWorkingDir := filepath.Join(root, "easy-rsa")
	pkiDir := filepath.Join(easyRSAWorkingDir, "pki")
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		t.Fatalf("create isolated synthetic PKI: %v", err)
	}
	indexPath := filepath.Join(pkiDir, "index.txt")
	if err := os.WriteFile(
		indexPath,
		[]byte(syntheticIndexLine(status, commonName, serialNumber)),
		0o600,
	); err != nil {
		t.Fatalf("write isolated synthetic PKI index: %v", err)
	}
	crlPath := filepath.Join(pkiDir, "crl.pem")
	if err := os.WriteFile(crlPath, []byte("synthetic-crl-before\n"), 0o600); err != nil {
		t.Fatalf("write isolated synthetic CRL: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(pkiDir, "test-certificate.crt"),
		[]byte("synthetic-public-certificate\n"),
		0o600,
	); err != nil {
		t.Fatalf("write isolated synthetic certificate: %v", err)
	}
	if ValidateCertificateCommonName(commonName) && status != "revoked" {
		writeSyntheticIssuedCertificate(
			t,
			filepath.Join(pkiDir, "issued", commonName+".crt"),
			commonName,
			serialNumber,
		)
	}

	databasePath := filepath.Join(root, "db", "data.db")
	if _, err := migrations.Up(context.Background(), databasePath); err != nil {
		t.Fatalf("initialize lifecycle test database: %v", err)
	}
	db, err := sql.Open(
		"sqlite3",
		fmt.Sprintf("file:%s?_busy_timeout=5000&_foreign_keys=on", databasePath),
	)
	if err != nil {
		t.Fatalf("open lifecycle test database: %v", err)
	}
	db.SetMaxOpenConns(4)
	revokedAt := any(nil)
	if status == "revoked" {
		revokedAt = lifecycleTestNow
	}
	staticIPValue := any(nil)
	if staticIP != "" {
		staticIPValue = staticIP
	}
	if _, err := db.Exec(`INSERT INTO certificates (
		id, common_name, serial_number, status, static_ip,
		technical_expires_at, revoked_at, created_at
	) VALUES (1, ?, ?, ?, ?, ?, ?, ?)`,
		commonName,
		serialNumber,
		status,
		staticIPValue,
		lifecycleTestNow.AddDate(1, 0, 0),
		revokedAt,
		lifecycleTestNow,
	); err != nil {
		db.Close()
		t.Fatalf("seed lifecycle certificate: %v", err)
	}

	service, err := NewCertificateLifecycleService(
		db,
		CertificateLifecycleConfig{
			EasyRSABinary:        filepath.Join(easyRSAWorkingDir, "easyrsa"),
			EasyRSAWorkingDir:    easyRSAWorkingDir,
			PKIDir:               pkiDir,
			ManagementNetwork:    "tcp",
			ManagementAddress:    "127.0.0.1:1",
			ProtectedCommonNames: []string{"protected-server"},
		},
	)
	if err != nil {
		db.Close()
		t.Fatalf("create lifecycle service: %v", err)
	}
	runner := &fakeLifecycleRunner{indexPath: indexPath, crlPath: crlPath}
	disconnector := &fakeLifecycleDisconnector{}
	service.runner = runner
	service.disconnector = disconnector
	service.now = func() time.Time { return lifecycleTestNow }
	return service, db, pkiDir, runner, disconnector
}

func syntheticIndexLine(status, commonName, serialNumber string) string {
	entryType := "V"
	revocation := ""
	if status == "revoked" {
		entryType = "R"
		revocation = "260723120000Z"
	}
	return strings.Join([]string{
		entryType,
		"270723120000Z",
		revocation,
		serialNumber,
		"unknown",
		"/C=CN/O=Test/CN=" + commonName,
	}, "\t") + "\n"
}

func writeSyntheticIssuedCertificate(
	t *testing.T,
	path string,
	commonName string,
	serialNumber string,
) {
	t.Helper()
	serial := new(big.Int)
	if _, ok := serial.SetString(serialNumber, 16); !ok {
		t.Fatalf("parse synthetic certificate serial %q", serialNumber)
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate synthetic certificate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    lifecycleTestNow.Add(-time.Hour),
		NotAfter:     lifecycleTestNow.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		t.Fatalf("create synthetic certificate: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create synthetic certificate directory: %v", err)
	}
	if err := os.WriteFile(
		path,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		0o600,
	); err != nil {
		t.Fatalf("write synthetic certificate: %v", err)
	}
}

func prepareSyntheticRenewal(
	t *testing.T,
	pkiDir string,
	commonName string,
	oldSerial string,
	newSerial string,
) {
	t.Helper()
	currentPath := filepath.Join(pkiDir, "issued", commonName+".crt")
	renewedPath := filepath.Join(
		pkiDir,
		"renewed",
		"issued",
		commonName+".crt",
	)
	if err := os.MkdirAll(filepath.Dir(renewedPath), 0o700); err != nil {
		t.Fatalf("create synthetic renewed certificate directory: %v", err)
	}
	if err := os.Rename(currentPath, renewedPath); err != nil {
		t.Fatalf("move synthetic certificate to renewed history: %v", err)
	}
	writeSyntheticIssuedCertificate(t, currentPath, commonName, newSerial)

	indexPath := filepath.Join(pkiDir, "index.txt")
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read synthetic renewal index: %v", err)
	}
	if !strings.Contains(string(indexData), "\t"+oldSerial+"\t") {
		t.Fatalf("synthetic renewal index does not contain old serial %s", oldSerial)
	}
	indexData = append(indexData, []byte(
		syntheticIndexLine("valid", commonName, newSerial),
	)...)
	if err := os.WriteFile(indexPath, indexData, 0o600); err != nil {
		t.Fatalf("write synthetic renewal index: %v", err)
	}
}

func adminLifecycleActor() CertificateLifecycleActor {
	return CertificateLifecycleActor{
		UserID:    1,
		IsAdmin:   true,
		SourceIP:  "192.0.2.10",
		RequestID: "request-lifecycle-test",
	}
}

func snapshotTestPKI(t *testing.T, pkiDir string) map[string][sha256.Size]byte {
	t.Helper()
	snapshot := make(map[string][sha256.Size]byte)
	err := filepath.WalkDir(pkiDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(pkiDir, path)
		if err != nil {
			return err
		}
		snapshot[relative] = sha256.Sum256(data)
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot isolated PKI: %v", err)
	}
	return snapshot
}

func assertRunnerUsesArgumentArrays(t *testing.T, runner *fakeLifecycleRunner) {
	t.Helper()
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.calls) != 2 {
		t.Fatalf("Easy-RSA call count = %d, want 2", len(runner.calls))
	}
	for _, call := range runner.calls {
		if call.Binary == "/bin/bash" || call.Binary == "/bin/sh" {
			t.Fatalf("lifecycle command used a shell: %+v", call)
		}
		for _, argument := range call.Args {
			if argument == "-c" {
				t.Fatalf("lifecycle command used shell command mode: %+v", call)
			}
		}
		if !reflect.DeepEqual(call.Environment, []string{"EASYRSA_BATCH=1"}) {
			t.Fatalf("unexpected Easy-RSA environment: %v", call.Environment)
		}
	}
	if got := runner.calls[0].Args[len(runner.calls[0].Args)-2:]; !reflect.DeepEqual(
		got,
		[]string{"revoke", "test-client"},
	) {
		t.Fatalf("revoke arguments = %v", runner.calls[0].Args)
	}
	if runner.calls[1].Args[len(runner.calls[1].Args)-1] != "gen-crl" {
		t.Fatalf("gen-crl arguments = %v", runner.calls[1].Args)
	}
}

func assertLifecycleAuditResults(
	t *testing.T,
	db *sql.DB,
	action string,
	expected []string,
) {
	t.Helper()
	rows, err := db.Query(`SELECT result FROM audit_logs
		WHERE action = ? ORDER BY id`, action)
	if err != nil {
		t.Fatalf("read lifecycle audit results: %v", err)
	}
	defer rows.Close()
	actual := make([]string, 0)
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			t.Fatalf("scan lifecycle audit result: %v", err)
		}
		actual = append(actual, result)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate lifecycle audit results: %v", err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("lifecycle audit results = %v, want %v", actual, expected)
	}
}

func assertLatestAuditError(t *testing.T, db *sql.DB, expected string) {
	t.Helper()
	var errorSummary string
	if err := db.QueryRow(`SELECT error_summary FROM audit_logs
		ORDER BY id DESC LIMIT 1`).Scan(&errorSummary); err != nil {
		t.Fatalf("read latest lifecycle audit error: %v", err)
	}
	if errorSummary != expected {
		t.Fatalf("latest audit error = %q, want %q", errorSummary, expected)
	}
}
