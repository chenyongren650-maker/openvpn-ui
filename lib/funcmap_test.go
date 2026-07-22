package lib

import (
	"regexp"
	"testing"
)

func TestFormatUnixTime(t *testing.T) {
	if got := formatUnixTime("0", "fallback"); !regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$`).MatchString(got) {
		t.Fatalf("formatUnixTime() = %q", got)
	}
	if got := formatUnixTime("invalid", "fallback"); got != "fallback" {
		t.Fatalf("formatUnixTime() fallback = %q", got)
	}
}
