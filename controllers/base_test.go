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
