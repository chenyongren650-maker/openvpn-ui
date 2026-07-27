package controllers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	webcontext "github.com/beego/beego/v2/server/web/context"
	"github.com/d3vilh/openvpn-ui/migrations"
	"github.com/d3vilh/openvpn-ui/models"
	"github.com/d3vilh/openvpn-ui/services"
)

const controllerSyntheticTOTPSeed = "3132333435363738393031323334353637383930"

type totpControllerFixture struct {
	service *services.TOTPService
	db      *sql.DB
}

func newTOTPControllerFixture(t *testing.T) *totpControllerFixture {
	t.Helper()
	root := t.TempDir()
	databasePath := filepath.Join(root, "db", "data.db")
	if _, err := migrations.Up(context.Background(), databasePath); err != nil {
		t.Fatalf("initialize controller TOTP database: %v", err)
	}
	dsn := &url.URL{Scheme: "file", Path: databasePath}
	query := dsn.Query()
	query.Set("_busy_timeout", "5000")
	query.Set("_foreign_keys", "on")
	query.Set("_txlock", "immediate")
	dsn.RawQuery = query.Encode()
	db, err := sql.Open("sqlite3", dsn.String())
	if err != nil {
		t.Fatalf("open controller TOTP database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`INSERT INTO certificates (
			id, common_name, serial_number, status
		) VALUES (1, 'controller-totp-client', 'A101', 'valid')`,
		`INSERT INTO totp_identities (
			certificate_id, tfa_name, issuer, status
		) VALUES (
			1, 'controller-totp@example.invalid', 'ZHISUAN', 'active'
		)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("seed controller TOTP database: %v", err)
		}
	}
	clientsDirectory := filepath.Join(root, "clients")
	if err := os.MkdirAll(clientsDirectory, 0o700); err != nil {
		t.Fatalf("create controller TOTP directory: %v", err)
	}
	oathPath := filepath.Join(clientsDirectory, "oath.secrets")
	if err := os.WriteFile(
		oathPath,
		[]byte(
			"controller-totp@example.invalid:"+
				controllerSyntheticTOTPSeed+
				"\n",
		),
		0o600,
	); err != nil {
		t.Fatalf("write controller synthetic oath.secrets: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(clientsDirectory, "controller-totp-client.png"),
		[]byte("controller-synthetic-png"),
		0o600,
	); err != nil {
		t.Fatalf("write controller synthetic QR code: %v", err)
	}
	qrBinary := filepath.Join(root, "synthetic-qrencode")
	if err := os.WriteFile(
		qrBinary,
		[]byte("#!/bin/sh\nprintf 'controller-reset-png'\n"),
		0o700,
	); err != nil {
		t.Fatalf("write synthetic QR generator: %v", err)
	}
	service, err := services.NewTOTPService(db, services.TOTPServiceConfig{
		OATHSecretsPath: oathPath,
		QRCodeDirectory: clientsDirectory,
		QRCodeBinary:    qrBinary,
		Issuer:          "ZHISUAN",
	})
	if err != nil {
		t.Fatalf("create controller TOTP service: %v", err)
	}
	return &totpControllerFixture{service: service, db: db}
}

func TestTOTPControllerRequiresAuthenticationPermissionAndCSRF(t *testing.T) {
	fixture := newTOTPControllerFixture(t)
	tests := []struct {
		name           string
		user           *models.User
		isLogin        bool
		csrf           string
		expectedStatus int
	}{
		{
			name:           "unauthenticated",
			csrf:           controllerTestCSRFToken,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "non-admin",
			user: &models.User{
				Id:      2,
				IsAdmin: false,
			},
			isLogin:        true,
			csrf:           controllerTestCSRFToken,
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "invalid CSRF",
			user: &models.User{
				Id:      1,
				IsAdmin: true,
			},
			isLogin:        true,
			csrf:           "invalid-session-token",
			expectedStatus: http.StatusForbidden,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller, response := newTOTPTestController(
				t,
				fixture.service,
				url.Values{
					"_csrf":        []string{test.csrf},
					"confirmation": []string{"controller-totp-client"},
				},
				test.user,
				test.isLogin,
			)
			controller.Secret()
			if response.Code != test.expectedStatus {
				t.Fatalf(
					"TOTP authorization response status = %d, want %d",
					response.Code,
					test.expectedStatus,
				)
			}
			assertTOTPNoCacheHeaders(t, response)
		})
	}
}

func TestTOTPControllerSecretResponseIsNoStoreAndAudited(t *testing.T) {
	fixture := newTOTPControllerFixture(t)
	controller, response := newTOTPTestController(
		t,
		fixture.service,
		url.Values{
			"_csrf":        []string{controllerTestCSRFToken},
			"confirmation": []string{"controller-totp-client"},
		},
		&models.User{Id: 1, IsAdmin: true},
		true,
	)
	controller.Secret()
	if response.Code != http.StatusOK {
		t.Fatalf("TOTP Secret response status = %d, want 200", response.Code)
	}
	assertTOTPNoCacheHeaders(t, response)
	var payload totpJSONResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode TOTP Secret response: %v", err)
	}
	if !payload.OK || payload.Base32Secret == "" ||
		payload.Base32Secret == controllerSyntheticTOTPSeed ||
		payload.RequestID != "controller-totp-request" {
		t.Fatal("TOTP Secret response did not contain the expected minimal data")
	}
	var action, requestID, result, summary, errorSummary string
	if err := fixture.db.QueryRow(`SELECT
		action, request_id, result, summary, error_summary
		FROM audit_logs ORDER BY id DESC LIMIT 1`).Scan(
		&action,
		&requestID,
		&result,
		&summary,
		&errorSummary,
	); err != nil {
		t.Fatalf("read TOTP Secret audit: %v", err)
	}
	if action != services.TOTPAuditActionSecretView ||
		requestID != "controller-totp-request" ||
		result != "success" ||
		strings.Contains(summary, payload.Base32Secret) ||
		strings.Contains(errorSummary, payload.Base32Secret) {
		t.Fatal("TOTP Secret audit is missing linkage or contains sensitive data")
	}
}

func TestTOTPControllerVerifyRejectsInvalidFormatWithoutEcho(t *testing.T) {
	fixture := newTOTPControllerFixture(t)
	controller, response := newTOTPTestController(
		t,
		fixture.service,
		url.Values{
			"_csrf": []string{controllerTestCSRFToken},
			"code":  []string{"not-six-digits"},
		},
		&models.User{Id: 1, IsAdmin: true},
		true,
	)
	controller.Verify()
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid TOTP format response = %d, want 400", response.Code)
	}
	assertTOTPNoCacheHeaders(t, response)
	if strings.Contains(response.Body.String(), "not-six-digits") {
		t.Fatal("TOTP error response echoed submitted code")
	}
	var summary, errorSummary string
	if err := fixture.db.QueryRow(`SELECT summary, error_summary
		FROM audit_logs ORDER BY id DESC LIMIT 1`).
		Scan(&summary, &errorSummary); err != nil {
		t.Fatalf("read invalid TOTP audit: %v", err)
	}
	if strings.Contains(summary, "not-six-digits") ||
		strings.Contains(errorSummary, "not-six-digits") {
		t.Fatal("TOTP audit echoed submitted code")
	}
}

func TestTOTPControllerResetRequiresStableIdempotencyKey(t *testing.T) {
	fixture := newTOTPControllerFixture(t)
	controller, response := newTOTPTestController(
		t,
		fixture.service,
		url.Values{
			"_csrf":           []string{controllerTestCSRFToken},
			"confirmation":    []string{"controller-totp-client"},
			"idempotency_key": []string{"controller-reset-key-0001"},
		},
		&models.User{Id: 1, IsAdmin: true},
		true,
	)
	controller.Reset()
	if response.Code != http.StatusOK {
		t.Fatalf("TOTP reset response = %d, want 200", response.Code)
	}
	assertTOTPNoCacheHeaders(t, response)
	var payload totpJSONResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode TOTP reset response: %v", err)
	}
	if !payload.OK || payload.OperationID <= 0 ||
		payload.Base32Secret == "" {
		t.Fatal("TOTP reset response is incomplete")
	}
}

func newTOTPTestController(
	t *testing.T,
	service *services.TOTPService,
	form url.Values,
	user *models.User,
	isLogin bool,
) (*TOTPController, *httptest.ResponseRecorder) {
	t.Helper()
	request := httptest.NewRequest(
		http.MethodPost,
		"http://example.invalid/certificates/1/totp",
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	ctx := webcontext.NewContext()
	ctx.Reset(response, request)
	ctx.Input.SetParam(":id", "1")
	session := &controllerTestSession{
		values: map[interface{}]interface{}{
			sessionCSRFKey: controllerTestCSRFToken,
		},
	}
	ctx.Input.CruSession = session

	controller := &TOTPController{Service: service}
	controller.Init(ctx, "TOTPController", "Secret", controller)
	controller.CruSession = session
	controller.Userinfo = user
	controller.IsLogin = isLogin
	controller.RequestID = "controller-totp-request"
	return controller, response
}

func assertTOTPNoCacheHeaders(
	t *testing.T,
	response *httptest.ResponseRecorder,
) {
	t.Helper()
	if !strings.Contains(
		response.Header().Get("Cache-Control"),
		"no-store",
	) ||
		response.Header().Get("Pragma") != "no-cache" ||
		response.Header().Get("Expires") != "0" {
		t.Fatal("TOTP response is missing no-cache headers")
	}
}
