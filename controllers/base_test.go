package controllers

import (
	"testing"

	"github.com/d3vilh/openvpn-ui/i18n"
)

func TestResolveLanguagePreferenceCookie(t *testing.T) {
	language, cookie := resolveLanguagePreference(i18n.EnglishLanguage, i18n.DefaultLanguage, true)
	if language != i18n.EnglishLanguage {
		t.Fatalf("language = %q, want %q", language, i18n.EnglishLanguage)
	}
	if cookie == nil {
		t.Fatal("supported query did not create cookie settings")
	}
	if cookie.MaxAge != languageCookieMaxAge || cookie.Path != "/" || !cookie.HTTPOnly || !cookie.Secure || cookie.SameSite != "Lax" {
		t.Fatalf("unexpected cookie settings: %#v", cookie)
	}
}

func TestResolveLanguagePreferenceDoesNotPersistInvalidQuery(t *testing.T) {
	language, cookie := resolveLanguagePreference("invalid", i18n.EnglishLanguage, false)
	if language != i18n.EnglishLanguage {
		t.Fatalf("language = %q, want cookie fallback %q", language, i18n.EnglishLanguage)
	}
	if cookie != nil {
		t.Fatalf("invalid query created cookie settings: %#v", cookie)
	}
}

func TestResolveLanguagePreferenceOmitsSecureOnHTTP(t *testing.T) {
	_, cookie := resolveLanguagePreference(i18n.DefaultLanguage, "", false)
	if cookie == nil || cookie.Secure {
		t.Fatalf("HTTP cookie settings = %#v", cookie)
	}
}

func TestSessionCSRFIsBoundToOneSessionToken(t *testing.T) {
	sessionToken, err := newRandomToken(32)
	if err != nil {
		t.Fatalf("create session CSRF token: %v", err)
	}
	otherSessionToken, err := newRandomToken(32)
	if err != nil {
		t.Fatalf("create second session CSRF token: %v", err)
	}
	if !validSessionCSRF(sessionToken, sessionToken) {
		t.Fatal("matching session CSRF token was rejected")
	}
	for _, presented := range []string{"", otherSessionToken, sessionToken[:len(sessionToken)-1]} {
		if validSessionCSRF(sessionToken, presented) {
			t.Fatalf("invalid session CSRF token was accepted: %q", presented)
		}
	}
}

func TestResolveRequestIDAcceptsSafeHeaderAndReplacesUnsafeInput(t *testing.T) {
	const supplied = "request-20260723.001"
	requestID, err := resolveRequestID(" " + supplied + " ")
	if err != nil || requestID != supplied {
		t.Fatalf("safe request ID = %q, error = %v", requestID, err)
	}

	generated, err := resolveRequestID("../../unsafe?request")
	if err != nil {
		t.Fatalf("generate replacement request ID: %v", err)
	}
	if generated == "../../unsafe?request" || !requestIDPattern.MatchString(generated) {
		t.Fatalf("unsafe request ID replacement = %q", generated)
	}
}
