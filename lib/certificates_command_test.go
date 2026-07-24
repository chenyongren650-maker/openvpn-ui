package lib

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCertificateCommandsUseArgumentArraysWithoutShell(t *testing.T) {
	request := CertificateCreationRequest{
		Name:       "safe-client-01",
		StaticIP:   "10.9.5.10",
		Passphrase: "synthetic-test-passphrase",
		ExpireDays: "825",
		Email:      "user@example.invalid",
		Country:    "CN",
		Province:   "Beijing",
		City:       "Beijing",
		Org:        "Test Org",
		OrgUnit:    "Operations",
		TFAName:    "user@example.invalid",
		TFAIssuer:  "ZHISUAN",
	}
	createCommand, err := buildCreateCertificateCommand(request)
	if err != nil {
		t.Fatalf("build safe create command: %v", err)
	}
	assertCertificateCommandIsShellFree(t, createCommand)
	if createCommand.binary != genClientScript ||
		!reflect.DeepEqual(
			createCommand.args[:2],
			[]string{"safe-client-01", "10.9.5.10"},
		) ||
		len(createCommand.args) != 3 {
		t.Fatal("create command did not preserve safe argument boundaries")
	}

}

func TestCertificateCreationRejectsCommandAndPathInjection(t *testing.T) {
	valid := CertificateCreationRequest{
		Name:       "safe-client-01",
		StaticIP:   "10.9.5.10",
		ExpireDays: "825",
		Email:      "user@example.invalid",
		TFAName:    "user@example.invalid",
		TFAIssuer:  "ZHISUAN",
	}
	tests := []struct {
		name   string
		mutate func(*CertificateCreationRequest)
	}{
		{
			name: "shell metacharacter in common name",
			mutate: func(request *CertificateCreationRequest) {
				request.Name = "client;touch"
			},
		},
		{
			name: "path traversal common name",
			mutate: func(request *CertificateCreationRequest) {
				request.Name = "../client"
			},
		},
		{
			name: "invalid static address",
			mutate: func(request *CertificateCreationRequest) {
				request.StaticIP = "10.9.5.10;id"
			},
		},
		{
			name: "newline in issuer",
			mutate: func(request *CertificateCreationRequest) {
				request.TFAIssuer = "ZHISUAN\nINJECTED"
			},
		},
		{
			name: "invalid expiration command",
			mutate: func(request *CertificateCreationRequest) {
				request.ExpireDays = "825;id"
			},
		},
		{
			name: "nul in organization",
			mutate: func(request *CertificateCreationRequest) {
				request.Org = "Test\x00Org"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			if _, err := buildCreateCertificateCommand(request); !errors.Is(
				err,
				ErrInvalidCertificateInput,
			) {
				t.Fatalf("unsafe certificate input error = %v", err)
			}
		})
	}
}

func TestCertificateCreationScriptDoesNotPrintTOTPMaterial(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "build", "assets", "genclient.sh"))
	if err != nil {
		t.Fatalf("read certificate creation script: %v", err)
	}
	script := string(data)
	for _, prohibited := range []string{
		"echo $QRSTRING",
		`echo "$TFA_NAME:$USERHASH"`,
		"tee -a $OATH_SECRETS",
		`sed -i'.bak' "$ s/$/`,
		"tail -1 $EASY_RSA/pki/index.txt",
	} {
		if strings.Contains(script, prohibited) {
			t.Fatalf("certificate creation script contains prohibited behavior %q", prohibited)
		}
	}
	if !strings.Contains(script, ".creation-complete") {
		t.Fatal("certificate creation script is missing its recovery completion marker")
	}
}

func TestWriteAtomicFileReplacesTargetWithRestrictedMode(t *testing.T) {
	target := filepath.Join(t.TempDir(), "static-client")
	if err := writeAtomicFile(target, []byte("first\n"), 0o600); err != nil {
		t.Fatalf("write first atomic certificate file: %v", err)
	}
	if err := writeAtomicFile(target, []byte("second\n"), 0o600); err != nil {
		t.Fatalf("replace atomic certificate file: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read atomic certificate file: %v", err)
	}
	if string(data) != "second\n" {
		t.Fatalf("atomic certificate file content = %q", data)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat atomic certificate file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("atomic certificate file mode = %o", info.Mode().Perm())
	}
}

func TestCertificateCreationPreparesStaticConfigBeforeCommand(t *testing.T) {
	root := newCertificateCreationTestRoot(t)
	request := certificateCreationTestRequest()
	commandCalls := 0
	err := createCertificate(
		request,
		root,
		func(certificateScriptCommand) error {
			commandCalls++
			staticPath := filepath.Join(root, "staticclients", request.Name)
			data, readErr := os.ReadFile(staticPath)
			if readErr != nil {
				t.Fatalf("read prepared static client configuration: %v", readErr)
			}
			if string(data) != "ifconfig-push 10.9.5.10 255.255.255.0\n" {
				t.Fatalf("prepared static client configuration = %q", data)
			}
			writeCompletedCertificateCreationArtifacts(t, root, request)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("create certificate with prepared static config: %v", err)
	}
	if commandCalls != 1 {
		t.Fatalf("certificate command calls = %d, want 1", commandCalls)
	}
}

func TestCertificateCreationDoesNotRunCommandWhenStaticConfigCannotBePrepared(
	t *testing.T,
) {
	root := newCertificateCreationTestRoot(t)
	request := certificateCreationTestRequest()
	staticDirectory := filepath.Join(root, "staticclients")
	if err := os.Remove(staticDirectory); err != nil {
		t.Fatalf("remove test static client directory: %v", err)
	}
	if err := os.WriteFile(staticDirectory, []byte("not-a-directory\n"), 0o600); err != nil {
		t.Fatalf("create blocked static client path: %v", err)
	}

	commandCalls := 0
	err := createCertificate(
		request,
		root,
		func(certificateScriptCommand) error {
			commandCalls++
			return nil
		},
	)
	if err == nil {
		t.Fatal("static configuration failure unexpectedly created a certificate")
	}
	if commandCalls != 0 {
		t.Fatalf("certificate command calls = %d, want 0", commandCalls)
	}
}

func TestCertificateCreationRollsBackOwnedStaticConfigBeforeIssuance(t *testing.T) {
	root := newCertificateCreationTestRoot(t)
	request := certificateCreationTestRequest()
	syntheticFailure := errors.New("synthetic command failure")

	err := createCertificate(
		request,
		root,
		func(certificateScriptCommand) error {
			return syntheticFailure
		},
	)
	if !errors.Is(err, syntheticFailure) {
		t.Fatalf("certificate command failure = %v", err)
	}
	if _, err := os.Stat(
		filepath.Join(root, "staticclients", request.Name),
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned static configuration was not rolled back: %v", err)
	}
}

func TestCertificateCreationKeepsStaticConfigWhenIssuanceStateIsUnknown(
	t *testing.T,
) {
	root := newCertificateCreationTestRoot(t)
	request := certificateCreationTestRequest()
	indexPath := filepath.Join(root, "pki", "index.txt")

	err := createCertificate(
		request,
		root,
		func(certificateScriptCommand) error {
			if removeErr := os.Remove(indexPath); removeErr != nil {
				t.Fatalf("remove synthetic certificate index: %v", removeErr)
			}
			return errors.New("synthetic command failure with unknown issuance state")
		},
	)
	if !errors.Is(err, ErrCertificateCreationIncomplete) {
		t.Fatalf("unknown certificate issuance state error = %v", err)
	}

	staticPath := filepath.Join(root, "staticclients", request.Name)
	data, readErr := os.ReadFile(staticPath)
	if readErr != nil {
		t.Fatalf("read preserved static client configuration: %v", readErr)
	}
	if string(data) != "ifconfig-push 10.9.5.10 255.255.255.0\n" {
		t.Fatalf("preserved static client configuration = %q", data)
	}
}

func TestCertificateCreationPartialFailureIsIdempotentlyReconciled(t *testing.T) {
	root := newCertificateCreationTestRoot(t)
	request := certificateCreationTestRequest()
	commandCalls := 0
	err := createCertificate(
		request,
		root,
		func(certificateScriptCommand) error {
			commandCalls++
			appendCertificateCreationIndexRecord(t, root, request)
			if err := os.WriteFile(
				filepath.Join(root, "clients", request.Name+".ovpn"),
				[]byte("synthetic-client-config\n"),
				0o600,
			); err != nil {
				t.Fatalf("write synthetic client configuration: %v", err)
			}
			return errors.New("synthetic failure before completion marker")
		},
	)
	if !errors.Is(err, ErrCertificateCreationIncomplete) {
		t.Fatalf("partial certificate creation error = %v", err)
	}
	if commandCalls != 1 {
		t.Fatalf("partial certificate command calls = %d, want 1", commandCalls)
	}

	indexPath := filepath.Join(root, "pki", "index.txt")
	indexBeforeRetry, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read synthetic index before retry: %v", err)
	}
	if err := os.WriteFile(
		certificateCreationMarkerPath(root, request.Name),
		[]byte(certificateCreationMarkerContent(request)),
		0o600,
	); err != nil {
		t.Fatalf("write synthetic completion marker: %v", err)
	}

	err = createCertificate(
		request,
		root,
		func(certificateScriptCommand) error {
			commandCalls++
			return errors.New("retry must not execute certificate command")
		},
	)
	if err != nil {
		t.Fatalf("reconcile completed certificate creation: %v", err)
	}
	if commandCalls != 1 {
		t.Fatalf("reconciled certificate command calls = %d, want 1", commandCalls)
	}
	indexAfterRetry, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read synthetic index after retry: %v", err)
	}
	if string(indexAfterRetry) != string(indexBeforeRetry) {
		t.Fatal("certificate creation retry changed PKI index history")
	}
}

func TestFindCertificateByNameUsesLatestHistoryRecord(t *testing.T) {
	historical := &Cert{
		Serial:  "01",
		Details: &Details{CN: "history-client", Name: "history-client"},
	}
	current := &Cert{
		Serial:  "02",
		Details: &Details{CN: "history-client", Name: "history-client"},
	}
	if found := findCertificateByName(
		[]*Cert{historical, current},
		"history-client",
	); found != current {
		t.Fatal("certificate history did not select the current record")
	}
}

func newCertificateCreationTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{"pki", "clients", "staticclients"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatalf("create certificate test directory %s: %v", directory, err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(root, "pki", "index.txt"),
		[]byte(
			"V\t270101000000Z\t\t01\tunknown\t/CN=server/name=server/LocalIP=dynamic.pool/2FAName=none\n",
		),
		0o600,
	); err != nil {
		t.Fatalf("write certificate test index: %v", err)
	}
	return root
}

func certificateCreationTestRequest() CertificateCreationRequest {
	return CertificateCreationRequest{
		Name:       "recovery-client",
		StaticIP:   "10.9.5.10",
		ExpireDays: "825",
		Email:      "recovery@example.invalid",
		TFAIssuer:  "ZHISUAN",
	}
}

func appendCertificateCreationIndexRecord(
	t *testing.T,
	root string,
	request CertificateCreationRequest,
) {
	t.Helper()
	indexPath := filepath.Join(root, "pki", "index.txt")
	file, err := os.OpenFile(indexPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open synthetic certificate index: %v", err)
	}
	defer file.Close()
	if _, err := fmt.Fprintf(
		file,
		"V\t270101000000Z\t\t02\tunknown\t/CN=%s\n",
		request.Name,
	); err != nil {
		t.Fatalf("append synthetic certificate index: %v", err)
	}
}

func writeCompletedCertificateCreationArtifacts(
	t *testing.T,
	root string,
	request CertificateCreationRequest,
) {
	t.Helper()
	appendCertificateCreationIndexRecord(t, root, request)
	if err := os.WriteFile(
		filepath.Join(root, "clients", request.Name+".ovpn"),
		[]byte("synthetic-client-config\n"),
		0o600,
	); err != nil {
		t.Fatalf("write synthetic client configuration: %v", err)
	}
	if request.TFAName != "" {
		if err := os.WriteFile(
			filepath.Join(root, "clients", request.Name+".png"),
			[]byte("synthetic-qr-image\n"),
			0o600,
		); err != nil {
			t.Fatalf("write synthetic QR image: %v", err)
		}
	}
	if err := os.WriteFile(
		certificateCreationMarkerPath(root, request.Name),
		[]byte(certificateCreationMarkerContent(request)),
		0o600,
	); err != nil {
		t.Fatalf("write synthetic completion marker: %v", err)
	}
}

func assertCertificateCommandIsShellFree(
	t *testing.T,
	command certificateScriptCommand,
) {
	t.Helper()
	if command.binary == "/bin/bash" || command.binary == "/bin/sh" {
		t.Fatalf("certificate command uses a shell binary: %s", command.binary)
	}
	for _, argument := range command.args {
		if argument == "-c" {
			t.Fatal("certificate command uses shell command mode")
		}
	}
	if command.workingDir != certificateScriptsDir {
		t.Fatalf("certificate command working directory = %q", command.workingDir)
	}
}
