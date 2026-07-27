package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/d3vilh/openvpn-ui/lib"
)

type fakeCertificateCreator struct {
	mu          sync.Mutex
	err         error
	invocations int
	signatures  int
	issued      map[string]struct{}
	requests    []lib.CertificateCreationRequest
}

func (f *fakeCertificateCreator) CreateCertificate(
	request lib.CertificateCreationRequest,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invocations++
	f.requests = append(f.requests, request)
	if f.err != nil {
		return f.err
	}
	if f.issued == nil {
		f.issued = make(map[string]struct{})
	}
	if _, exists := f.issued[request.Name]; !exists {
		f.issued[request.Name] = struct{}{}
		f.signatures++
	}
	return nil
}

type fakeCertificateMetadataSyncer struct {
	mu        sync.Mutex
	db        *sql.DB
	failCount int
	nextID    int64
}

func (f *fakeCertificateMetadataSyncer) SyncCreatedCertificateMetadata(
	ctx context.Context,
	commonName string,
	staticIP string,
	tfaName string,
	issuer string,
) (CertificateImportResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failCount > 0 {
		f.failCount--
		return CertificateImportResult{}, errors.New("synthetic metadata sync failure")
	}
	staticIPValue := any(nil)
	if staticIP != "" {
		staticIPValue = staticIP
	}
	var certificateID int64
	err := f.db.QueryRowContext(ctx, `SELECT id FROM certificates
		WHERE common_name = ? AND status = 'valid'
		ORDER BY id DESC LIMIT 1`,
		commonName,
	).Scan(&certificateID)
	if errors.Is(err, sql.ErrNoRows) {
		f.nextID++
		serial := fmt.Sprintf("D%03d", f.nextID)
		result, insertErr := f.db.ExecContext(ctx, `INSERT INTO certificates (
			common_name, serial_number, status, static_ip
		) VALUES (?, ?, 'valid', ?)`,
			commonName,
			serial,
			staticIPValue,
		)
		if insertErr != nil {
			return CertificateImportResult{}, insertErr
		}
		certificateID, insertErr = result.LastInsertId()
		if insertErr != nil {
			return CertificateImportResult{}, insertErr
		}
	} else if err != nil {
		return CertificateImportResult{}, err
	} else {
		if _, err := f.db.ExecContext(ctx, `UPDATE certificates
			SET static_ip = ? WHERE id = ?`,
			staticIPValue,
			certificateID,
		); err != nil {
			return CertificateImportResult{}, err
		}
	}
	if tfaName != "" {
		if _, err := f.db.ExecContext(ctx, `INSERT INTO totp_identities (
			certificate_id, tfa_name, issuer, status
		) VALUES (?, ?, ?, 'active')
		ON CONFLICT(certificate_id) DO UPDATE SET
			tfa_name = excluded.tfa_name,
			issuer = excluded.issuer,
			status = 'active'`,
			certificateID,
			tfaName,
			issuer,
		); err != nil {
			return CertificateImportResult{}, err
		}
	}
	return CertificateImportResult{}, nil
}

func TestUserCertificateProvisioningCreatesNormalUserWithoutStaticIP(t *testing.T) {
	fixture, creator, _, service := newProvisioningTestService(t)
	defer fixture.close()

	input := validProvisioningInput("normal-client", PermissionTypeNormal)
	input.TFAName = ""
	result, err := service.Provision(
		context.Background(),
		input,
		testProvisioningActor(),
	)
	if err != nil {
		t.Fatalf("provision normal user: %v", err)
	}
	if result.VPNUserID <= 0 || result.CertificateID <= 0 ||
		result.StaticIP != "" || result.RecoveryRequired {
		t.Fatalf("normal provisioning result = %+v", result)
	}

	var permissionType string
	var staticIP sql.NullString
	var vpnUserID int64
	if err := fixture.db.QueryRow(`SELECT
		vpn_user_id, permission_type, static_ip
		FROM certificates WHERE id = ?`,
		result.CertificateID,
	).Scan(&vpnUserID, &permissionType, &staticIP); err != nil {
		t.Fatalf("read normal certificate metadata: %v", err)
	}
	if vpnUserID != result.VPNUserID ||
		permissionType != PermissionTypeNormal ||
		staticIP.Valid {
		t.Fatalf(
			"normal certificate metadata user=%d permission=%s static=%v",
			vpnUserID,
			permissionType,
			staticIP,
		)
	}
	var allocationCount int
	if err := fixture.db.QueryRow(
		`SELECT COUNT(*) FROM ip_allocations`,
	).Scan(&allocationCount); err != nil {
		t.Fatalf("count normal allocations: %v", err)
	}
	if allocationCount != 0 {
		t.Fatalf("normal allocation count = %d, want 0", allocationCount)
	}
	if creator.requests[0].StaticIP != "" ||
		creator.requests[0].TFAName != input.Email ||
		creator.requests[0].TFAIssuer != defaultTFAIssuer {
		t.Fatalf("normal certificate creation request = %+v", creator.requests[0])
	}
	assertProvisioningAuditResults(t, fixture.db, "started", "success")
}

func TestUserCertificateProvisioningCreatesRestrictedUserAndCompletesReservation(t *testing.T) {
	fixture, creator, _, service := newProvisioningTestService(t)
	defer fixture.close()

	input := validProvisioningInput(
		"restricted-client",
		PermissionTypeRestricted,
	)
	result, err := service.Provision(
		context.Background(),
		input,
		testProvisioningActor(),
	)
	if err != nil {
		t.Fatalf("provision restricted user: %v", err)
	}
	if result.StaticIP != "10.9.5.10" ||
		result.VPNUserID <= 0 ||
		result.CertificateID <= 0 {
		t.Fatalf("restricted provisioning result = %+v", result)
	}
	if creator.requests[0].StaticIP != "10.9.5.10" {
		t.Fatalf("certificate static IP = %s", creator.requests[0].StaticIP)
	}

	var reservationStatus, allocationStatus, allocatedIP string
	if err := fixture.db.QueryRow(`SELECT status
		FROM ip_allocation_reservations
		WHERE certificate_name = 'restricted-client'`,
	).Scan(&reservationStatus); err != nil {
		t.Fatalf("read completed reservation: %v", err)
	}
	if err := fixture.db.QueryRow(`SELECT ip_address, status
		FROM ip_allocations WHERE certificate_id = ?`,
		result.CertificateID,
	).Scan(&allocatedIP, &allocationStatus); err != nil {
		t.Fatalf("read completed allocation: %v", err)
	}
	if reservationStatus != "completed" ||
		allocationStatus != "allocated" ||
		allocatedIP != result.StaticIP {
		t.Fatalf(
			"reservation=%s allocation=%s ip=%s",
			reservationStatus,
			allocationStatus,
			allocatedIP,
		)
	}
	var actorUserID int64
	var sourceIP, requestID, summary string
	if err := fixture.db.QueryRow(`SELECT
		actor_user_id, source_ip, request_id, summary
		FROM audit_logs
		WHERE action = ? AND result = 'success'
		ORDER BY id DESC LIMIT 1`,
		UserCertificateAuditActionProvision,
	).Scan(
		&actorUserID,
		&sourceIP,
		&requestID,
		&summary,
	); err != nil {
		t.Fatalf("read restricted provisioning audit: %v", err)
	}
	if actorUserID != 1 ||
		sourceIP != "192.0.2.10" ||
		requestID != "provision-request-1" ||
		!strings.Contains(summary, "vpn_user_id=") ||
		!strings.Contains(summary, "permission_type=restricted") ||
		!strings.Contains(summary, "allocation=10.9.5.10") {
		t.Fatalf(
			"restricted audit actor=%d source=%s request=%s summary=%q",
			actorUserID,
			sourceIP,
			requestID,
			summary,
		)
	}
	assertProvisioningAuditResults(t, fixture.db, "started", "success")
}

func TestUserCertificateProvisioningReusesMatchingVPNUser(t *testing.T) {
	fixture, _, _, service := newProvisioningTestService(t)
	defer fixture.close()
	firstInput := validProvisioningInput(
		"shared-user-client-01",
		PermissionTypeNormal,
	)
	firstInput.Username = "shared-user"
	firstInput.Email = "shared-user@example.invalid"
	firstInput.TFAName = firstInput.Email
	firstResult, err := service.Provision(
		context.Background(),
		firstInput,
		testProvisioningActor(),
	)
	if err != nil {
		t.Fatalf("provision first shared-user certificate: %v", err)
	}

	secondInput := firstInput
	secondInput.CertificateName = "shared-user-client-02"
	secondInput.TFAName = "shared-user-02@example.invalid"
	secondActor := testProvisioningActor()
	secondActor.RequestID = "provision-shared-user-2"
	secondResult, err := service.Provision(
		context.Background(),
		secondInput,
		secondActor,
	)
	if err != nil {
		t.Fatalf("provision second shared-user certificate: %v", err)
	}
	if secondResult.VPNUserID != firstResult.VPNUserID {
		t.Fatalf(
			"second VPN user ID = %d, want %d",
			secondResult.VPNUserID,
			firstResult.VPNUserID,
		)
	}
	var userCount, certificateCount int
	if err := fixture.db.QueryRow(
		`SELECT COUNT(*) FROM vpn_users`,
	).Scan(&userCount); err != nil {
		t.Fatalf("count shared VPN users: %v", err)
	}
	if err := fixture.db.QueryRow(
		`SELECT COUNT(*) FROM certificates WHERE vpn_user_id = ?`,
		firstResult.VPNUserID,
	).Scan(&certificateCount); err != nil {
		t.Fatalf("count shared-user certificates: %v", err)
	}
	if userCount != 1 || certificateCount != 2 {
		t.Fatalf(
			"shared user count=%d certificate count=%d, want 1 and 2",
			userCount,
			certificateCount,
		)
	}
}

func TestUserCertificateProvisioningRejectsVPNUserIdentityConflicts(t *testing.T) {
	fixture, creator, _, service := newProvisioningTestService(t)
	defer fixture.close()
	firstInput := validProvisioningInput(
		"identity-client-01",
		PermissionTypeNormal,
	)
	firstInput.Username = "identity-user"
	firstInput.Email = "identity-user@example.invalid"
	firstInput.TFAName = firstInput.Email
	if _, err := service.Provision(
		context.Background(),
		firstInput,
		testProvisioningActor(),
	); err != nil {
		t.Fatalf("seed VPN user identity: %v", err)
	}

	conflictingInput := firstInput
	conflictingInput.CertificateName = "identity-client-02"
	conflictingInput.Email = "different-email@example.invalid"
	conflictingInput.TFAName = conflictingInput.Email
	conflictingActor := testProvisioningActor()
	conflictingActor.RequestID = "provision-identity-conflict"
	if _, err := service.Provision(
		context.Background(),
		conflictingInput,
		conflictingActor,
	); !errors.Is(err, ErrUserProvisioningConflict) {
		t.Fatalf("VPN user identity conflict error = %v", err)
	}
	if creator.signatures != 1 {
		t.Fatalf(
			"certificate signatures after identity conflict = %d, want 1",
			creator.signatures,
		)
	}
}

func TestUserCertificateProvisioningCompensatesBeforeIssuance(t *testing.T) {
	fixture, creator, _, service := newProvisioningTestService(t)
	defer fixture.close()
	creator.err = errors.New("synthetic certificate command failure")

	result, err := service.Provision(
		context.Background(),
		validProvisioningInput("failed-client", PermissionTypeRestricted),
		testProvisioningActor(),
	)
	if err == nil || result.RecoveryRequired {
		t.Fatalf("pre-issuance failure result=%+v err=%v", result, err)
	}

	var userCount int
	if queryErr := fixture.db.QueryRow(
		`SELECT COUNT(*) FROM vpn_users`,
	).Scan(&userCount); queryErr != nil {
		t.Fatalf("count compensated users: %v", queryErr)
	}
	if userCount != 0 {
		t.Fatalf("VPN user count after compensation = %d, want 0", userCount)
	}
	var reservationStatus string
	if queryErr := fixture.db.QueryRow(`SELECT status
		FROM ip_allocation_reservations
		WHERE certificate_name = 'failed-client'`,
	).Scan(&reservationStatus); queryErr != nil {
		t.Fatalf("read compensated reservation: %v", queryErr)
	}
	if reservationStatus != "released" {
		t.Fatalf("reservation status = %s, want released", reservationStatus)
	}
	assertProvisioningAuditResults(t, fixture.db, "started", "failed")
}

func TestUserCertificateProvisioningPreservesReservationAfterIssuance(t *testing.T) {
	fixture, creator, _, service := newProvisioningTestService(t)
	defer fixture.close()
	creator.err = lib.ErrCertificateCreationIncomplete

	result, err := service.Provision(
		context.Background(),
		validProvisioningInput("recovery-client", PermissionTypeRestricted),
		testProvisioningActor(),
	)
	if !errors.Is(err, ErrUserProvisioningRecoveryRequired) ||
		!result.RecoveryRequired {
		t.Fatalf("incomplete creation result=%+v err=%v", result, err)
	}

	var status, errorSummary string
	if queryErr := fixture.db.QueryRow(`SELECT status, error_summary
		FROM ip_allocation_reservations
		WHERE certificate_name = 'recovery-client'`,
	).Scan(&status, &errorSummary); queryErr != nil {
		t.Fatalf("read recovery reservation: %v", queryErr)
	}
	if status != "reserved" || errorSummary != "certificate_creation_incomplete" {
		t.Fatalf("recovery reservation status=%s error=%s", status, errorSummary)
	}
	var userCount int
	if queryErr := fixture.db.QueryRow(
		`SELECT COUNT(*) FROM vpn_users`,
	).Scan(&userCount); queryErr != nil {
		t.Fatalf("count retained recovery user: %v", queryErr)
	}
	if userCount != 1 {
		t.Fatalf("retained recovery user count = %d, want 1", userCount)
	}
}

func TestUserCertificateProvisioningRetryDoesNotRepeatIssuance(t *testing.T) {
	fixture, creator, syncer, service := newProvisioningTestService(t)
	defer fixture.close()
	syncer.failCount = 1
	input := validProvisioningInput("retry-provision", PermissionTypeRestricted)

	first, err := service.Provision(
		context.Background(),
		input,
		testProvisioningActor(),
	)
	if !errors.Is(err, ErrUserProvisioningRecoveryRequired) ||
		!first.RecoveryRequired {
		t.Fatalf("first retry result=%+v err=%v", first, err)
	}
	secondActor := testProvisioningActor()
	secondActor.RequestID = "provision-request-retry"
	second, err := service.Provision(
		context.Background(),
		input,
		secondActor,
	)
	if err != nil {
		t.Fatalf("retry provisioning: %v", err)
	}
	if second.StaticIP != first.StaticIP || !second.Retried {
		t.Fatalf("retry result=%+v, first=%+v", second, first)
	}
	if creator.invocations != 2 || creator.signatures != 1 {
		t.Fatalf(
			"creator invocations=%d signatures=%d, want 2 and 1",
			creator.invocations,
			creator.signatures,
		)
	}
	var reservationCount int
	if err := fixture.db.QueryRow(`SELECT COUNT(*)
		FROM ip_allocation_reservations
		WHERE certificate_name = 'retry-provision'`,
	).Scan(&reservationCount); err != nil {
		t.Fatalf("count retry reservations: %v", err)
	}
	if reservationCount != 1 {
		t.Fatalf("retry reservation count = %d, want 1", reservationCount)
	}
}

func TestUserCertificateProvisioningCompletedRetryIsIdempotent(t *testing.T) {
	fixture, creator, _, service := newProvisioningTestService(t)
	defer fixture.close()
	input := validProvisioningInput(
		"completed-retry-client",
		PermissionTypeRestricted,
	)
	first, err := service.Provision(
		context.Background(),
		input,
		testProvisioningActor(),
	)
	if err != nil {
		t.Fatalf("first completed provisioning: %v", err)
	}
	retryActor := testProvisioningActor()
	retryActor.RequestID = "provision-completed-retry"
	second, err := service.Provision(
		context.Background(),
		input,
		retryActor,
	)
	if err != nil {
		t.Fatalf("repeat completed provisioning: %v", err)
	}
	if second.VPNUserID != first.VPNUserID ||
		second.CertificateID != first.CertificateID ||
		second.StaticIP != first.StaticIP ||
		!second.Retried {
		t.Fatalf("completed retry first=%+v second=%+v", first, second)
	}
	if creator.signatures != 1 {
		t.Fatalf(
			"completed retry certificate signatures = %d, want 1",
			creator.signatures,
		)
	}
	var reservationCount, allocationCount int
	if err := fixture.db.QueryRow(`SELECT COUNT(*)
		FROM ip_allocation_reservations
		WHERE certificate_name = 'completed-retry-client'`,
	).Scan(&reservationCount); err != nil {
		t.Fatalf("count completed retry reservations: %v", err)
	}
	if err := fixture.db.QueryRow(`SELECT COUNT(*)
		FROM ip_allocations WHERE certificate_id = ?`,
		first.CertificateID,
	).Scan(&allocationCount); err != nil {
		t.Fatalf("count completed retry allocations: %v", err)
	}
	if reservationCount != 1 || allocationCount != 1 {
		t.Fatalf(
			"completed retry reservations=%d allocations=%d, want 1 and 1",
			reservationCount,
			allocationCount,
		)
	}
}

func TestUserCertificateProvisioningDatabaseFailureRequiresRecovery(t *testing.T) {
	fixture, _, _, service := newProvisioningTestService(t)
	defer fixture.close()
	if _, err := fixture.db.Exec(`CREATE TRIGGER fail_provisioning_commit
		BEFORE UPDATE OF vpn_user_id ON certificates
		BEGIN
			SELECT RAISE(ABORT, 'synthetic commit failure');
		END`); err != nil {
		t.Fatalf("create synthetic commit failure: %v", err)
	}

	result, err := service.Provision(
		context.Background(),
		validProvisioningInput("commit-failure", PermissionTypeRestricted),
		testProvisioningActor(),
	)
	if !errors.Is(err, ErrUserProvisioningRecoveryRequired) ||
		!result.RecoveryRequired {
		t.Fatalf("database failure result=%+v err=%v", result, err)
	}
	var status, errorSummary string
	if queryErr := fixture.db.QueryRow(`SELECT status, error_summary
		FROM ip_allocation_reservations
		WHERE certificate_name = 'commit-failure'`,
	).Scan(&status, &errorSummary); queryErr != nil {
		t.Fatalf("read commit failure reservation: %v", queryErr)
	}
	if status != "reserved" || errorSummary != "database_commit_failed" {
		t.Fatalf("commit failure reservation status=%s error=%s", status, errorSummary)
	}
	var allocationCount int
	if queryErr := fixture.db.QueryRow(
		`SELECT COUNT(*) FROM ip_allocations`,
	).Scan(&allocationCount); queryErr != nil {
		t.Fatalf("count rolled back allocations: %v", queryErr)
	}
	if allocationCount != 0 {
		t.Fatalf("rolled back allocation count = %d, want 0", allocationCount)
	}
}

func TestUserCertificateProvisioningEnforcesAuthorizationAuditAndInputSafety(t *testing.T) {
	t.Run("non administrator", func(t *testing.T) {
		fixture, creator, _, service := newProvisioningTestService(t)
		defer fixture.close()
		actor := testProvisioningActor()
		actor.IsAdmin = false

		_, err := service.Provision(
			context.Background(),
			validProvisioningInput("forbidden-client", PermissionTypeNormal),
			actor,
		)
		if !errors.Is(err, ErrUserProvisioningForbidden) {
			t.Fatalf("non-admin error = %v", err)
		}
		if creator.invocations != 0 {
			t.Fatalf("non-admin creator invocations = %d", creator.invocations)
		}
	})

	t.Run("audit unavailable", func(t *testing.T) {
		fixture, creator, _, service := newProvisioningTestService(t)
		defer fixture.close()
		if _, err := fixture.db.Exec(`DROP TABLE audit_logs`); err != nil {
			t.Fatalf("drop audit table: %v", err)
		}

		_, err := service.Provision(
			context.Background(),
			validProvisioningInput("audit-client", PermissionTypeNormal),
			testProvisioningActor(),
		)
		if !errors.Is(err, ErrUserProvisioningAuditUnavailable) {
			t.Fatalf("audit unavailable error = %v", err)
		}
		if creator.invocations != 0 {
			t.Fatalf("audit failure creator invocations = %d", creator.invocations)
		}
		var userCount int
		if queryErr := fixture.db.QueryRow(
			`SELECT COUNT(*) FROM vpn_users`,
		).Scan(&userCount); queryErr != nil {
			t.Fatalf("count users after audit failure: %v", queryErr)
		}
		if userCount != 0 {
			t.Fatalf("users after audit failure = %d, want 0", userCount)
		}
	})

	t.Run("injection and traversal", func(t *testing.T) {
		fixture, creator, _, service := newProvisioningTestService(t)
		defer fixture.close()
		for index, certificateName := range []string{
			"../escape",
			"client;touch-pwned",
			"client\nother",
		} {
			input := validProvisioningInput(
				certificateName,
				PermissionTypeRestricted,
			)
			input.Username = fmt.Sprintf("invalid-user-%d", index)
			input.Email = fmt.Sprintf("invalid-%d@example.invalid", index)
			input.TFAName = input.Email
			_, err := service.Provision(
				context.Background(),
				input,
				testProvisioningActor(),
			)
			if !errors.Is(err, ErrUserProvisioningInvalidInput) {
				t.Fatalf("certificate name %q error = %v", certificateName, err)
			}
		}
		if creator.invocations != 0 {
			t.Fatalf("invalid input creator invocations = %d", creator.invocations)
		}
	})

	t.Run("control characters", func(t *testing.T) {
		fixture, creator, _, service := newProvisioningTestService(t)
		defer fixture.close()
		input := validProvisioningInput(
			"control-character-client",
			PermissionTypeNormal,
		)
		input.DisplayName = "Test\tEmployee"
		_, err := service.Provision(
			context.Background(),
			input,
			testProvisioningActor(),
		)
		if !errors.Is(err, ErrUserProvisioningInvalidInput) {
			t.Fatalf("control-character input error = %v", err)
		}
		if creator.invocations != 0 {
			t.Fatalf(
				"control-character creator invocations = %d",
				creator.invocations,
			)
		}
	})
}

func TestUserCertificateProvisioningAuditDoesNotContainSensitiveInput(t *testing.T) {
	fixture, _, _, service := newProvisioningTestService(t)
	defer fixture.close()
	input := validProvisioningInput("sensitive-client", PermissionTypeNormal)
	input.Passphrase = "test-passphrase-must-not-be-recorded"

	if _, err := service.Provision(
		context.Background(),
		input,
		testProvisioningActor(),
	); err != nil {
		t.Fatalf("provision sensitive input test: %v", err)
	}
	rows, err := fixture.db.Query(`SELECT
		action, target_id, summary, result, error_summary, request_id
		FROM audit_logs`)
	if err != nil {
		t.Fatalf("read provisioning audit: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var values [6]string
		if err := rows.Scan(
			&values[0],
			&values[1],
			&values[2],
			&values[3],
			&values[4],
			&values[5],
		); err != nil {
			t.Fatalf("scan provisioning audit: %v", err)
		}
		for _, value := range values {
			if strings.Contains(value, input.Passphrase) {
				t.Fatal("audit contains certificate passphrase")
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate provisioning audit: %v", err)
	}
}

func newProvisioningTestService(
	t *testing.T,
) (
	*restrictedIPTestFixture,
	*fakeCertificateCreator,
	*fakeCertificateMetadataSyncer,
	*UserCertificateProvisioningService,
) {
	t.Helper()
	fixture := newRestrictedIPTestFixture(t)
	creator := &fakeCertificateCreator{}
	syncer := &fakeCertificateMetadataSyncer{db: fixture.db}
	service, err := NewUserCertificateProvisioningService(
		fixture.db,
		fixture.service,
		creator,
		syncer,
	)
	if err != nil {
		fixture.close()
		t.Fatalf("create user certificate provisioning service: %v", err)
	}
	service.now = fixture.service.now
	return fixture, creator, syncer, service
}

func validProvisioningInput(
	certificateName string,
	permissionType string,
) UserCertificateProvisioningInput {
	username := strings.ReplaceAll(certificateName, "client", "user")
	email := username + "@example.invalid"
	return UserCertificateProvisioningInput{
		DisplayName:     "Test Employee",
		Username:        username,
		Email:           email,
		Department:      "Quality Assurance",
		CertificateName: certificateName,
		TFAName:         email,
		TFAIssuer:       "ZHISUAN",
		PermissionType:  permissionType,
		ExpireDays:      "825",
		DeviceNote:      "Test device",
		BusinessNote:    "Synthetic test record",
		Country:         "CN",
		Province:        "GD",
		City:            "Guangzhou",
		Org:             "TEST",
		OrgUnit:         "QA",
	}
}

func testProvisioningActor() CertificateLifecycleActor {
	return CertificateLifecycleActor{
		UserID:    1,
		IsAdmin:   true,
		SourceIP:  "192.0.2.10",
		RequestID: "provision-request-1",
	}
}

func assertProvisioningAuditResults(
	t *testing.T,
	db *sql.DB,
	expected ...string,
) {
	t.Helper()
	rows, err := db.Query(`SELECT result FROM audit_logs
		WHERE action = ?
		ORDER BY id`,
		UserCertificateAuditActionProvision,
	)
	if err != nil {
		t.Fatalf("read provisioning audit results: %v", err)
	}
	defer rows.Close()
	var actual []string
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			t.Fatalf("scan provisioning audit result: %v", err)
		}
		actual = append(actual, result)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate provisioning audit results: %v", err)
	}
	if strings.Join(actual, ",") != strings.Join(expected, ",") {
		t.Fatalf("audit results = %v, want %v", actual, expected)
	}
}
