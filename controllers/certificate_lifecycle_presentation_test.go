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
	} {
		if !strings.Contains(routes, required) {
			t.Fatalf("generated certificate routes are missing %q", required)
		}
	}
	for _, prohibited := range []string{
		"/certificates/burn/",
		"/certificates/revoke/:key",
		"/certificates/renew/:key",
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
