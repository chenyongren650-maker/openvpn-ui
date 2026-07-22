package controllers

import (
	"strings"
	"testing"
)

func TestSanitizeTechnicalDetail(t *testing.T) {
	detail := sanitizeTechnicalDetail("password=secret token:abc Authorization: Bearer abc.def 2FA code: 123456")
	for _, secret := range []string{"=secret", ":abc", "abc.def", "123456"} {
		if strings.Contains(detail, secret) {
			t.Fatalf("sanitized detail still contains %q: %q", secret, detail)
		}
	}
}

func TestSanitizeTechnicalDetailRemovesPEMAndTruncates(t *testing.T) {
	detail := "-----BEGIN PRIVATE KEY-----\nprivate-data\n-----END PRIVATE KEY-----\n" + strings.Repeat("x", maxTechnicalDetailLength+100)
	got := sanitizeTechnicalDetail(detail)
	if strings.Contains(got, "private-data") {
		t.Fatalf("sanitized detail contains PEM data: %q", got)
	}
	if len(got) > maxTechnicalDetailLength+len("…") {
		t.Fatalf("sanitized detail length = %d", len(got))
	}
}
