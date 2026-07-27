package controllers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	clientconfig "github.com/d3vilh/openvpn-server-config/client/client-config"
)

func TestCertificateLifecyclePageUsesPostDatabaseIDAndSessionCSRF(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "views", "certificates.html"))
	if err != nil {
		t.Fatalf("read certificate template: %v", err)
	}
	template := string(data)
	for _, required := range []string{
		`method="post" action="{{urlfor "CertificatesController.Revoke" ":id" .ID}}"`,
		`method="post" action="{{urlfor "CertificatesController.Archive" ":id" .ID}}"`,
		`method="post" action="{{urlfor "CertificatesController.Renew" ":id" .ID}}"`,
		`method="post" action="{{urlfor "CertificatesController.Restart"}}"`,
		`method="post" action="{{urlfor "CertificatesController.Reload"}}"`,
		`name="_csrf" value="{{$.SessionCSRFToken}}"`,
		`name="confirmation"`,
		`"CertificatesController.Download" ":id" .ID`,
		`"CertificatesController.TOTPQRCode" ":id" .ID`,
		`id="certificate-{{ .ID }}-modal"`,
		`data-target="#certificate-{{ .ID }}-modal"`,
		`(or (eq .LifecycleStatus "valid") (eq .LifecycleStatus "expired"))`,
	} {
		if !strings.Contains(template, required) {
			t.Fatalf("certificate template is missing %q", required)
		}
	}
	for _, prohibited := range []string{
		"CertificatesController.Burn",
		`href="{{urlfor "CertificatesController.Revoke"`,
		`href="{{urlfor "CertificatesController.Renew"`,
		`":key" .Details.Name ":localip"`,
		`href="{{urlfor "CertificatesController.Restart"`,
		`javascript:$.MyAPP.Restart`,
		`name="tfa_name"`,
		`/displayimage/`,
		`id="{{ .Details.CN }}-modal"`,
	} {
		if strings.Contains(template, prohibited) {
			t.Fatalf("certificate template still contains legacy lifecycle route %q", prohibited)
		}
	}
}

func TestCertificateLifecycleRoutesUsePostAndStableDatabaseID(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "routers", "commentsRouter_controllers.go"))
	if err != nil {
		t.Fatalf("read generated controller routes: %v", err)
	}
	routes := string(data)
	for _, required := range []string{
		"Router:           `/certificates/:id/revoke`",
		"Router:           `/certificates/:id/archive`",
		"Router:           `/certificates/:id/renew`",
		`AllowHTTPMethods: []string{"post"}`,
		"Router:           `/certificates/:id/download`",
		"Router:           `/certificates/:id/totp-qr`",
	} {
		if !strings.Contains(routes, required) {
			t.Fatalf("generated certificate routes are missing %q", required)
		}
	}
	for _, prohibited := range []string{
		"/certificates/burn/",
		"/certificates/revoke/:key",
		"/certificates/renew/:key",
		"/displayimage/:imageName",
	} {
		if strings.Contains(routes, prohibited) {
			t.Fatalf("generated routes still contain legacy path %q", prohibited)
		}
	}

	controllerData, err := os.ReadFile("certificates.go")
	if err != nil {
		t.Fatalf("read certificate controller: %v", err)
	}
	controller := string(controllerData)
	for _, prohibited := range []string{
		"@router /certificates/restart [get]",
		"@router /certificates/reload [get]",
		"@router /certificates/:id/renew [get]",
		"@router /certificates/renew/:key/:localip/:serial/:tfaname",
	} {
		if strings.Contains(controller, prohibited) {
			t.Fatalf("certificate controller still contains GET write route %q", prohibited)
		}
	}
}

func TestGeneratedClientConfigurationUsesPrivateFilePermissions(t *testing.T) {
	root := t.TempDir()
	templatePath := filepath.Join(root, "client.tpl")
	destinationPath := filepath.Join(root, "test-client.ovpn")
	if err := os.WriteFile(templatePath, []byte("client\n{{.Cert}}\n"), 0o600); err != nil {
		t.Fatalf("write test client template: %v", err)
	}
	config := clientconfig.New()
	config.Cert = "synthetic-public-certificate"
	if err := SaveToFile(templatePath, config, destinationPath); err != nil {
		t.Fatalf("write generated client configuration: %v", err)
	}
	info, err := os.Stat(destinationPath)
	if err != nil {
		t.Fatalf("stat generated client configuration: %v", err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("client configuration permissions = %04o, want 0600", permissions)
	}
}

func TestTOTPManagementPageUsesProtectedPOSTFlows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "views", "certificates.html"))
	if err != nil {
		t.Fatalf("read certificate template: %v", err)
	}
	page := string(data)
	for _, required := range []string{
		`"TOTPController.Secret" ":id" .ID`,
		`"TOTPController.Verify" ":id" .ID`,
		`"TOTPController.Reset" ":id" .ID`,
		`name="_csrf" value="{{$.SessionCSRFToken}}"`,
		`name="idempotency_key" value=""`,
		`class="totp-json-form totp-secret-form"`,
		`class="totp-json-form totp-verify-form"`,
		`class="totp-json-form totp-reset-form"`,
		`URL.revokeObjectURL`,
		`clearTOTPSecret`,
		`window.addEventListener('pagehide'`,
		`window.crypto.randomUUID`,
		`{{t $.Localizer "totp.secret_mask"}}`,
	} {
		if !strings.Contains(page, required) {
			t.Fatalf("TOTP management page is missing %q", required)
		}
	}
	for _, prohibited := range []string{
		`localStorage`,
		`sessionStorage`,
		`console.log`,
		`method="get"`,
		`name="hex_seed"`,
	} {
		if strings.Contains(page, prohibited) {
			t.Fatalf("TOTP management page contains prohibited fragment %q", prohibited)
		}
	}

	routerData, err := os.ReadFile(filepath.Join("..", "routers", "router.go"))
	if err != nil {
		t.Fatalf("read explicit routes: %v", err)
	}
	routes := string(routerData)
	for _, required := range []string{
		`"/certificates/:id/totp-secret"`,
		`"/certificates/:id/totp-verify"`,
		`"/certificates/:id/totp-reset"`,
		`"post:Secret"`,
		`"post:Verify"`,
		`"post:Reset"`,
	} {
		if !strings.Contains(routes, required) {
			t.Fatalf("TOTP routes are missing %q", required)
		}
	}
}
