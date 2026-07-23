package lib

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
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
