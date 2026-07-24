package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	webcontext "github.com/beego/beego/v2/server/web/context"
	"github.com/d3vilh/openvpn-ui/models"
)

type controllerTestSession struct {
	values map[interface{}]interface{}
}

func (s *controllerTestSession) Set(
	_ context.Context,
	key interface{},
	value interface{},
) error {
	s.values[key] = value
	return nil
}

func (s *controllerTestSession) Get(
	_ context.Context,
	key interface{},
) interface{} {
	return s.values[key]
}

func (s *controllerTestSession) Delete(
	_ context.Context,
	key interface{},
) error {
	delete(s.values, key)
	return nil
}

func (s *controllerTestSession) SessionID(context.Context) string {
	return "controller-test-session"
}

func (s *controllerTestSession) SessionReleaseIfPresent(
	context.Context,
	http.ResponseWriter,
) {
}

func (s *controllerTestSession) SessionRelease(
	context.Context,
	http.ResponseWriter,
) {
}

func (s *controllerTestSession) Flush(context.Context) error {
	clear(s.values)
	return nil
}

func TestCertificateWriteControllersRejectInvalidSessionCSRF(t *testing.T) {
	actions := []struct {
		name string
		run  func(*CertificatesController)
	}{
		{name: "create", run: func(controller *CertificatesController) { controller.Post() }},
		{name: "revoke", run: func(controller *CertificatesController) { controller.Revoke() }},
		{name: "archive", run: func(controller *CertificatesController) { controller.Archive() }},
		{name: "renew", run: func(controller *CertificatesController) { controller.Renew() }},
		{name: "TOTP QR", run: func(controller *CertificatesController) { controller.TOTPQRCode() }},
		{name: "restart", run: func(controller *CertificatesController) { controller.Restart() }},
		{name: "reload", run: func(controller *CertificatesController) { controller.Reload() }},
	}
	for _, action := range actions {
		t.Run(action.name, func(t *testing.T) {
			controller, response := newCertificateWriteController(
				t,
				"wrong-session-token",
				&models.User{Id: 1, IsAdmin: true},
			)
			action.run(controller)
			if response.Code != http.StatusForbidden {
				t.Fatalf("invalid CSRF response status = %d, want 403", response.Code)
			}
		})
	}
}

func TestCertificateAdministrativeControllersRejectNonAdmin(t *testing.T) {
	actions := []struct {
		name string
		run  func(*CertificatesController)
	}{
		{name: "create", run: func(controller *CertificatesController) { controller.Post() }},
		{name: "restart", run: func(controller *CertificatesController) { controller.Restart() }},
		{name: "reload", run: func(controller *CertificatesController) { controller.Reload() }},
	}
	for _, action := range actions {
		t.Run(action.name, func(t *testing.T) {
			controller, response := newCertificateWriteController(
				t,
				controllerTestCSRFToken,
				&models.User{Id: 2, IsAdmin: false},
			)
			action.run(controller)
			if response.Code != http.StatusForbidden {
				t.Fatalf("non-admin response status = %d, want 403", response.Code)
			}
		})
	}
}

const controllerTestCSRFToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newCertificateWriteController(
	t *testing.T,
	presentedCSRF string,
	user *models.User,
) (*CertificatesController, *httptest.ResponseRecorder) {
	t.Helper()
	form := url.Values{"_csrf": []string{presentedCSRF}}
	request := httptest.NewRequest(
		http.MethodPost,
		"http://example.invalid/certificates",
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	ctx := webcontext.NewContext()
	ctx.Reset(response, request)
	session := &controllerTestSession{
		values: map[interface{}]interface{}{
			sessionCSRFKey: controllerTestCSRFToken,
		},
	}
	ctx.Input.CruSession = session

	controller := &CertificatesController{}
	controller.Init(ctx, "CertificatesController", "Post", controller)
	controller.CruSession = session
	controller.Userinfo = user
	return controller, response
}
