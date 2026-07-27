package controllers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/d3vilh/openvpn-ui/services"
)

type TOTPController struct {
	BaseController
	Service *services.TOTPService
}

type totpJSONResponse struct {
	OK             bool   `json:"ok"`
	Message        string `json:"message,omitempty"`
	RequestID      string `json:"request_id"`
	Base32Secret   string `json:"base32_secret,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	TFAName        string `json:"tfa_name,omitempty"`
	Status         string `json:"status,omitempty"`
	CreatedAt      string `json:"created_at,omitempty"`
	ResetAt        string `json:"reset_at,omitempty"`
	LastVerifiedAt string `json:"last_verified_at,omitempty"`
	OperationID    int64  `json:"operation_id,omitempty"`
	Recovered      bool   `json:"recovered,omitempty"`
}

func (c *TOTPController) Secret() {
	c.setTOTPSensitiveResponseHeaders()
	certificateID, actor, ok := c.authorizeTOTPOperation(
		services.TOTPAuditActionSecretView,
		services.CanViewTOTPSecret,
	)
	if !ok {
		return
	}
	confirmation := c.GetString("confirmation")
	if len(confirmation) == 0 || len(confirmation) > 128 {
		c.recordTOTPAuditFailure(
			actor,
			services.TOTPAuditActionSecretView,
			certificateID,
			"confirmation_invalid",
		)
		c.renderTOTPError(http.StatusBadRequest, "totp.invalid_input")
		return
	}
	result, err := c.Service.ViewSecret(
		c.Ctx.Request.Context(),
		certificateID,
		confirmation,
		actor,
	)
	if err != nil {
		logs.Error("ERR_TOTP_SECRET_VIEW")
		status, key := c.totpErrorPresentation(err)
		c.renderTOTPError(status, key)
		return
	}
	response := totpMetadataResponse(result.TOTPIdentityMetadata)
	response.OK = true
	response.RequestID = c.RequestID
	response.Base32Secret = result.Base32Secret
	c.renderTOTPJSON(http.StatusOK, response)
}

func (c *TOTPController) Verify() {
	c.setTOTPSensitiveResponseHeaders()
	certificateID, actor, ok := c.authorizeTOTPOperation(
		services.TOTPAuditActionVerify,
		services.CanVerifyTOTP,
	)
	if !ok {
		return
	}
	code := c.GetString("code")
	if len(code) > 6 {
		c.recordTOTPAuditFailure(
			actor,
			services.TOTPAuditActionVerify,
			certificateID,
			"verification_format",
		)
		c.renderTOTPError(http.StatusBadRequest, "totp.code_format")
		return
	}
	if err := c.Service.Verify(
		c.Ctx.Request.Context(),
		certificateID,
		code,
		actor,
	); err != nil {
		logs.Error("ERR_TOTP_VERIFY")
		status, key := c.totpErrorPresentation(err)
		c.renderTOTPError(status, key)
		return
	}
	c.renderTOTPJSON(http.StatusOK, totpJSONResponse{
		OK:        true,
		Message:   c.T("totp.verify_success"),
		RequestID: c.RequestID,
	})
}

func (c *TOTPController) Reset() {
	c.setTOTPSensitiveResponseHeaders()
	certificateID, actor, ok := c.authorizeTOTPOperation(
		services.TOTPAuditActionReset,
		services.CanResetTOTP,
	)
	if !ok {
		return
	}
	confirmation := c.GetString("confirmation")
	idempotencyKey := c.GetString("idempotency_key")
	if len(confirmation) == 0 || len(confirmation) > 128 ||
		len(idempotencyKey) > 128 {
		c.recordTOTPAuditFailure(
			actor,
			services.TOTPAuditActionReset,
			certificateID,
			"reset_input_invalid",
		)
		c.renderTOTPError(http.StatusBadRequest, "totp.invalid_input")
		return
	}
	result, err := c.Service.Reset(
		c.Ctx.Request.Context(),
		certificateID,
		confirmation,
		idempotencyKey,
		actor,
	)
	if err != nil {
		logs.Error("ERR_TOTP_RESET")
		status, key := c.totpErrorPresentation(err)
		c.renderTOTPError(status, key)
		return
	}
	response := totpMetadataResponse(result.TOTPIdentityMetadata)
	response.OK = true
	response.Message = c.T("totp.reset_success")
	response.RequestID = c.RequestID
	response.Base32Secret = result.Base32Secret
	response.OperationID = result.OperationID
	response.Recovered = result.Recovered
	c.renderTOTPJSON(http.StatusOK, response)
}

func (c *TOTPController) authorizeTOTPOperation(
	action string,
	capability func(services.CertificateLifecycleActor) bool,
) (int64, services.CertificateLifecycleActor, bool) {
	actor := c.totpActor()
	if c.Service == nil {
		c.renderTOTPError(
			http.StatusServiceUnavailable,
			"totp.service_unavailable",
		)
		return 0, actor, false
	}
	certificateID, err := strconv.ParseInt(c.GetString(":id"), 10, 64)
	if err != nil || certificateID <= 0 {
		c.recordTOTPAuditFailure(
			actor,
			action,
			0,
			"invalid_target",
		)
		c.renderTOTPError(http.StatusNotFound, "certificate.not_found")
		return 0, actor, false
	}
	if c.Userinfo == nil || !c.IsLogin {
		c.recordTOTPAuditFailure(
			actor,
			action,
			certificateID,
			"authentication_required",
		)
		c.renderTOTPError(http.StatusUnauthorized, "error.login_required")
		return 0, actor, false
	}
	if capability == nil || !capability(actor) {
		c.recordTOTPAuditFailure(
			actor,
			action,
			certificateID,
			"permission_denied",
		)
		c.renderTOTPError(http.StatusForbidden, "error.admin_required")
		return 0, actor, false
	}
	if !c.ValidSessionCSRF() {
		c.recordTOTPAuditFailure(
			actor,
			action,
			certificateID,
			"csrf_invalid",
		)
		c.renderTOTPError(http.StatusForbidden, "error.csrf_invalid")
		return 0, actor, false
	}
	return certificateID, actor, true
}

func (c *TOTPController) totpActor() services.CertificateLifecycleActor {
	actor := services.CertificateLifecycleActor{
		SourceIP:  c.Ctx.Input.IP(),
		RequestID: c.RequestID,
	}
	if c.Userinfo != nil {
		actor.UserID = c.Userinfo.Id
		actor.IsAdmin = c.Userinfo.IsAdmin
	}
	return actor
}

func (c *TOTPController) recordTOTPAuditFailure(
	actor services.CertificateLifecycleActor,
	action string,
	certificateID int64,
	errorSummary string,
) {
	if c.Service == nil {
		return
	}
	if err := c.Service.RecordOperationAudit(
		c.Ctx.Request.Context(),
		actor,
		action,
		certificateID,
		errorSummary,
	); err != nil {
		logs.Error("ERR_TOTP_AUDIT_WRITE")
	}
}

func (c *TOTPController) setTOTPSensitiveResponseHeaders() {
	c.Ctx.Output.Header(
		"Cache-Control",
		"no-store, no-cache, must-revalidate, private",
	)
	c.Ctx.Output.Header("Pragma", "no-cache")
	c.Ctx.Output.Header("Expires", "0")
}

func (c *TOTPController) renderTOTPError(status int, key string) {
	c.renderTOTPJSON(status, totpJSONResponse{
		OK:        false,
		Message:   c.T(key),
		RequestID: c.RequestID,
	})
}

func (c *TOTPController) renderTOTPJSON(
	status int,
	response totpJSONResponse,
) {
	c.Ctx.Output.SetStatus(status)
	c.Data["json"] = response
	c.ServeJSON()
}

func (c *TOTPController) totpErrorPresentation(err error) (int, string) {
	switch {
	case errors.Is(err, services.ErrTOTPForbidden):
		return http.StatusForbidden, "error.admin_required"
	case errors.Is(err, services.ErrTOTPNotFound):
		return http.StatusNotFound, "certificate.not_found"
	case errors.Is(err, services.ErrTOTPConfirmation):
		return http.StatusConflict, "certificate.confirmation_mismatch"
	case errors.Is(err, services.ErrTOTPCodeFormat):
		return http.StatusBadRequest, "totp.code_format"
	case errors.Is(err, services.ErrTOTPInvalidInput):
		return http.StatusBadRequest, "totp.invalid_input"
	case errors.Is(err, services.ErrTOTPCodeInvalid):
		return http.StatusUnprocessableEntity, "totp.verify_failed"
	case errors.Is(err, services.ErrTOTPRateLimited):
		return http.StatusTooManyRequests, "totp.rate_limited"
	case errors.Is(err, services.ErrTOTPResetConflict):
		return http.StatusConflict, "totp.reset_conflict"
	case errors.Is(err, services.ErrTOTPCompensationRequired):
		return http.StatusConflict, "totp.compensation_required"
	case errors.Is(err, services.ErrTOTPInvalidState):
		return http.StatusConflict, "totp.invalid_state"
	case errors.Is(err, services.ErrTOTPAuditUnavailable):
		return http.StatusServiceUnavailable, "error.audit_unavailable"
	case errors.Is(err, services.ErrTOTPSecretUnavailable),
		errors.Is(err, services.ErrTOTPQRCodeUnavailable):
		return http.StatusConflict, "totp.data_unavailable"
	default:
		return http.StatusInternalServerError, "totp.operation_failed"
	}
}

func totpMetadataResponse(
	metadata services.TOTPIdentityMetadata,
) totpJSONResponse {
	response := totpJSONResponse{
		Issuer:    metadata.Issuer,
		TFAName:   metadata.TFAName,
		Status:    metadata.Status,
		CreatedAt: metadata.CreatedAt.UTC().Format(time.RFC3339),
	}
	if metadata.ResetAt != nil {
		response.ResetAt = metadata.ResetAt.UTC().Format(time.RFC3339)
	}
	if metadata.LastVerifiedAt != nil {
		response.LastVerifiedAt = metadata.LastVerifiedAt.UTC().Format(time.RFC3339)
	}
	return response
}
