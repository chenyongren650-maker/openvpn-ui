package controllers

import (
	"regexp"
	"strings"

	"github.com/beego/beego/v2/server/web"
)

const maxTechnicalDetailLength = 800

var sensitiveDetailPattern = regexp.MustCompile(`(?i)(password|passphrase|secret|token|otp|totp|authorization|private[ _-]?key|code)(\s*[:=]\s*)[^\s,;]+`)
var bearerTokenPattern = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+`)
var totpCodePattern = regexp.MustCompile(`\b[0-9]{6}\b`)
var pemBlockPattern = regexp.MustCompile(`(?s)-----BEGIN [^-]+-----.*?-----END [^-]+-----`)

func (c *BaseController) FlashSuccess(flash *web.FlashData, key string, args ...interface{}) {
	flash.Success(c.T(key, args...))
}

func (c *BaseController) FlashWarning(flash *web.FlashData, key string, args ...interface{}) {
	flash.Warning(c.T(key, args...))
}

// FlashError adds a localized summary and an optional, sanitized technical detail.
// exposeDetail must remain false for authentication, OAuth, certificate, 2FA, and
// external-command errors.
func (c *BaseController) FlashError(flash *web.FlashData, key, code string, err error, exposeDetail bool) {
	flash.Error(c.T(key))
	flash.Set("error_code", code)
	if exposeDetail && err != nil {
		flash.Set("error_detail", sanitizeTechnicalDetail(err.Error()))
	}
}

func sanitizeTechnicalDetail(detail string) string {
	detail = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(detail, "\r\n", "\n"), "\r", "\n"))
	detail = pemBlockPattern.ReplaceAllString(detail, "[redacted PEM data]")
	detail = bearerTokenPattern.ReplaceAllString(detail, "Bearer [redacted]")
	detail = sensitiveDetailPattern.ReplaceAllString(detail, "$1$2[redacted]")
	detail = totpCodePattern.ReplaceAllString(detail, "[redacted code]")
	runes := []rune(detail)
	if len(runes) > maxTechnicalDetailLength {
		detail = string(runes[:maxTechnicalDetailLength]) + "…"
	}
	return detail
}
