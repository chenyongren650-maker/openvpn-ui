package controllers

import (
	"os"
	"strings"
	"testing"

	"github.com/d3vilh/openvpn-ui/services"
)

func TestUserCertificateProvisioningInputDoesNotAcceptManualStaticIP(t *testing.T) {
	params := NewCertParams{
		DisplayName:    "Test Employee",
		Username:       "test-user",
		Department:     "QA",
		PermissionType: services.PermissionTypeRestricted,
		DeviceNote:     "Test device",
		BusinessNote:   "Test business note",
		Name:           "test-user-client",
		ExpireDays:     "825",
		Email:          "test-user@example.invalid",
		TFAName:        "test-user@example.invalid",
		TFAIssuer:      "ZHISUAN",
	}
	input := userCertificateProvisioningInput(params)
	if input.DisplayName != params.DisplayName ||
		input.Username != params.Username ||
		input.PermissionType != services.PermissionTypeRestricted ||
		input.CertificateName != params.Name ||
		input.Email != params.Email {
		t.Fatalf("provisioning input = %+v", input)
	}
	certificateRequest := certificateCreationRequest(params)
	if certificateRequest.StaticIP != "" {
		t.Fatalf(
			"controller certificate request static IP = %q, want empty",
			certificateRequest.StaticIP,
		)
	}
}

func TestCertificateCreationFormUsesAutomaticRestrictedAddressSelection(
	t *testing.T,
) {
	templateData, err := os.ReadFile("../views/certificates.html")
	if err != nil {
		t.Fatalf("read certificate template: %v", err)
	}
	templateText := string(templateData)
	for _, required := range []string{
		`name="DisplayName"`,
		`name="Username"`,
		`name="PermissionType" value="normal"`,
		`name="PermissionType" value="restricted"`,
		`name="DeviceNote"`,
		`name="BusinessNote"`,
		`certificate.permission_restricted_help`,
	} {
		if !strings.Contains(templateText, required) {
			t.Fatalf("certificate form missing %q", required)
		}
	}
	if strings.Contains(templateText, `name="staticip"`) {
		t.Fatal("certificate form still exposes manual static IP input")
	}
}
