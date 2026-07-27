package controllers

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/core/validation"
	"github.com/beego/beego/v2/server/web"
	clientconfig "github.com/d3vilh/openvpn-server-config/client/client-config"
	mi "github.com/d3vilh/openvpn-server-config/server/mi"
	"github.com/d3vilh/openvpn-ui/i18n"
	"github.com/d3vilh/openvpn-ui/lib"
	"github.com/d3vilh/openvpn-ui/models"
	"github.com/d3vilh/openvpn-ui/services"
	"github.com/d3vilh/openvpn-ui/state"
)

type NewCertParams struct {
	DisplayName    string `form:"DisplayName" valid:"Required;"`
	Username       string `form:"Username" valid:"Required;"`
	Department     string `form:"Department"`
	PermissionType string `form:"PermissionType" valid:"Required;"`
	DeviceNote     string `form:"DeviceNote"`
	BusinessNote   string `form:"BusinessNote"`
	Name           string `form:"Name" valid:"Required;"`
	Passphrase     string `form:"passphrase"`
	ExpireDays     string `form:"EasyRSACertExpire"`
	Email          string `form:"EasyRSAReqEmail" valid:"Required;Email"`
	Country        string `form:"EasyRSAReqCountry"`
	Province       string `form:"EasyRSAReqProvince"`
	City           string `form:"EasyRSAReqCity"`
	Org            string `form:"EasyRSAReqOrg"`
	OrgUnit        string `form:"EasyRSAReqOu"`
	TFAName        string `form:"TFAName"`
	TFAIssuer      string `form:"TFAIssuer"`
}

type CertificatesController struct {
	BaseController
	ConfigDir           string
	LifecycleService    *services.CertificateLifecycleService
	ProvisioningService *services.UserCertificateProvisioningService
}

type CertificatePageRecord struct {
	*lib.Cert
	ID              int64
	CommonName      string
	LifecycleStatus string
	DownloadAllowed bool
	RenewAllowed    bool
	Protected       bool
}

func (c *CertificatesController) NestPrepare() {
	if !c.IsLogin {
		c.Ctx.Redirect(302, c.LoginPath())
		return
	}
	c.Data["breadcrumbs"] = &BreadCrumbs{
		Title: c.T("breadcrumb.certificates"),
	}
	c.Data["CanManageCertificates"] = c.Userinfo != nil && c.Userinfo.IsAdmin
}

// @router /certificates/:id/download [get]
func (c *CertificatesController) Download() {
	certificateID, err := c.certificateID()
	if err != nil || c.LifecycleService == nil {
		c.renderCertificateHTTPError(http.StatusNotFound, "certificate.not_found")
		return
	}
	responseStarted := false
	err = c.LifecycleService.PerformCertificateDownload(
		c.Ctx.Request.Context(),
		certificateID,
		c.lifecycleActor(),
		func(certificateState services.CertificateState) error {
			name := certificateState.CommonName
			filename := fmt.Sprintf("%s.ovpn", name)
			keysPath := filepath.Join(state.GlobalCfg.OVConfigPath, "pki", "issued")

			cfgPath, err := c.saveClientConfig(keysPath, name)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(cfgPath)
			if err != nil {
				return err
			}
			c.Ctx.Output.Header("Content-Type", "application/octet-stream")
			c.Ctx.Output.Header(
				"Content-Disposition",
				fmt.Sprintf("attachment; filename=\"%s\"", filename),
			)
			responseStarted = true
			_, err = c.Controller.Ctx.ResponseWriter.Write(data)
			return err
		},
	)
	if err != nil {
		if responseStarted {
			logs.Error("ERR_CERT_DOWNLOAD_WRITE")
			return
		}
		status := http.StatusConflict
		key := "certificate.download_blocked"
		if errors.Is(err, services.ErrCertificateNotFound) {
			status = http.StatusNotFound
			key = "certificate.not_found"
		} else if errors.Is(err, services.ErrCertificateForbidden) {
			status = http.StatusForbidden
			key = "error.admin_required"
		} else if !errors.Is(err, services.ErrCertificateDownloadBlocked) &&
			!errors.Is(err, services.ErrCertificateIdentity) {
			status = http.StatusInternalServerError
			key = "certificate.download_failed"
		}
		logs.Error("ERR_CERT_DOWNLOAD")
		c.renderCertificateHTTPError(status, key)
	}
}

// @router /certificates [get]
func (c *CertificatesController) Get() {
	c.TplName = "certificates.html"
	c.Data["ShowArchived"] = c.GetString("view") == "archived"
	c.showCerts()
	cfg := models.EasyRSAConfig{Profile: "default"}
	_ = cfg.Read("Profile")
	c.Data["EasyRSA"] = &cfg

	cfg1 := models.OVClientConfig{Profile: "default"}
	_ = cfg1.Read("Profile")
	c.Data["SettingsC"] = &cfg1
}

// @router /certificates/:id/totp-qr [post]
func (c *CertificatesController) TOTPQRCode() {
	if !c.ValidSessionCSRF() {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionTOTPQR,
			c.GetString(":id"),
			"failed",
			"csrf_invalid",
		)
		c.renderCertificateHTTPError(http.StatusForbidden, "error.csrf_invalid")
		return
	}
	certificateID, err := c.certificateID()
	if err != nil || c.LifecycleService == nil {
		c.renderCertificateHTTPError(http.StatusNotFound, "certificate.not_found")
		return
	}

	responseStarted := false
	err = c.LifecycleService.PerformCertificateTOTPQRCodeView(
		c.Ctx.Request.Context(),
		certificateID,
		c.GetString("confirmation"),
		c.lifecycleActor(),
		func(certificateState services.CertificateState) error {
			imagePath := filepath.Join(
				state.GlobalCfg.OVConfigPath,
				"clients",
				certificateState.CommonName+".png",
			)
			data, err := os.ReadFile(imagePath)
			if err != nil {
				return err
			}
			c.Ctx.Output.Header("Content-Type", "image/png")
			responseStarted = true
			c.Ctx.Output.Body(data)
			return nil
		},
	)
	if err == nil || responseStarted {
		if err != nil {
			logs.Error("ERR_CERT_TOTP_QR_AUDIT")
		}
		return
	}

	status := http.StatusConflict
	key := "certificate.qr_view_blocked"
	switch {
	case errors.Is(err, services.ErrCertificateNotFound):
		status = http.StatusNotFound
		key = "certificate.not_found"
	case errors.Is(err, services.ErrCertificateForbidden):
		status = http.StatusForbidden
		key = "error.admin_required"
	case errors.Is(err, services.ErrCertificateConfirmation):
		status = http.StatusConflict
		key = "certificate.confirmation_mismatch"
	case errors.Is(err, os.ErrNotExist):
		status = http.StatusNotFound
		key = "certificate.image_not_found"
	case errors.Is(err, services.ErrCertificateTOTPQRBlocked),
		errors.Is(err, services.ErrCertificateDownloadBlocked),
		errors.Is(err, services.ErrCertificateIdentity):
		status = http.StatusConflict
		key = "certificate.qr_view_blocked"
	default:
		status = http.StatusInternalServerError
		key = "certificate.qr_view_failed"
	}
	logs.Error("ERR_CERT_TOTP_QR")
	c.renderCertificateHTTPError(status, key)
}

func (c *CertificatesController) showCerts() {
	path := filepath.Join(state.GlobalCfg.OVConfigPath, "pki/index.txt")
	certs, err := lib.ReadCerts(path)
	if err != nil {
		logs.Error("ERR_CERT_LIST_PKI")
		c.Data["certificates"] = []*CertificatePageRecord{}
		return
	}
	if c.LifecycleService == nil {
		logs.Error("ERR_CERT_LIFECYCLE_UNAVAILABLE")
		c.Data["certificates"] = []*CertificatePageRecord{}
		return
	}
	showArchived, _ := c.Data["ShowArchived"].(bool)
	states, err := c.LifecycleService.ListCertificateStates(
		c.Ctx.Request.Context(),
		showArchived,
	)
	if err != nil {
		logs.Error("ERR_CERT_LIST_DATABASE")
		c.Data["certificates"] = []*CertificatePageRecord{}
		return
	}
	stateBySerial := make(map[string]services.CertificateState, len(states))
	for _, certificateState := range states {
		stateBySerial[strings.ToUpper(certificateState.SerialNumber)] = certificateState
	}
	pageRecords := make([]*CertificatePageRecord, 0, len(states))
	for _, certificate := range certs {
		certificateState, exists := stateBySerial[strings.ToUpper(certificate.Serial)]
		if !exists || certificateState.Protected {
			continue
		}
		currentIssued, err := c.LifecycleService.IsCurrentIssuedCertificate(
			c.Ctx.Request.Context(),
			certificateState.ID,
		)
		if err != nil {
			logs.Error("ERR_CERT_CURRENT_IDENTITY")
			currentIssued = false
		}
		if certificate.Details != nil {
			certificate.Details.Name = certificateState.CommonName
			certificate.Details.TFAName = certificateState.TFAName
			if certificateState.StaticIP != "" {
				certificate.Details.LocalIP = certificateState.StaticIP
			}
		}
		pageRecords = append(pageRecords, &CertificatePageRecord{
			Cert:            certificate,
			ID:              certificateState.ID,
			CommonName:      certificateState.CommonName,
			LifecycleStatus: certificateState.Status,
			DownloadAllowed: c.canManageCertificates() &&
				currentIssued &&
				certificateState.Status == "valid" &&
				certificate.EntryType == "V" &&
				certificate.Revocation == "",
			RenewAllowed: currentIssued &&
				(certificateState.Status == "valid" ||
					certificateState.Status == "expired") &&
				certificate.Revocation == "",
			Protected: certificateState.Protected,
		})
	}
	c.Data["certificates"] = pageRecords
	cfg := models.EasyRSAConfig{Profile: "default"}
	_ = cfg.Read("Profile")
	c.Data["EasyRSA"] = &cfg
	cfg1 := models.OVClientConfig{Profile: "default"}
	_ = cfg1.Read("Profile")
	c.Data["SettingsC"] = &cfg1
}

// @router /certificates [post]
func (c *CertificatesController) Post() {
	if !c.ValidSessionCSRF() {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionCreate,
			"",
			"failed",
			"csrf_invalid",
		)
		c.renderCertificateHTTPError(http.StatusForbidden, "error.csrf_invalid")
		return
	}
	if !c.canManageCertificates() {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionCreate,
			"",
			"failed",
			"permission_denied",
		)
		c.renderCertificateHTTPError(http.StatusForbidden, "error.admin_required")
		return
	}
	c.TplName = "certificates.html"
	flash := web.NewFlash()

	cParams := NewCertParams{}
	if err := c.ParseForm(&cParams); err != nil {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionCreate,
			"",
			"failed",
			"form_parse_failed",
		)
		logs.Error("ERR_CERT_FORM")
		c.FlashError(flash, "error.form_parse", "ERR_CERT_FORM", err, false)
		flash.Store(&c.Controller)
	} else {
		if vMap := validateCertParams(cParams, c.Localizer); vMap != nil {
			c.recordCertificateOperationAudit(
				services.CertificateAuditActionCreate,
				cParams.Name,
				"failed",
				"invalid_input",
			)
			c.Data["validation"] = vMap
		} else if c.ProvisioningService == nil {
			logs.Error("ERR_USER_PROVISIONING_UNAVAILABLE")
			c.renderCertificateHTTPError(
				http.StatusServiceUnavailable,
				"certificate.provisioning_unavailable",
			)
			return
		} else {
			logs.Info(
				"Controller: Provisioning VPN user certificate: Name=%s, PermissionType=%s",
				cParams.Name,
				cParams.PermissionType,
			)
			result, err := c.ProvisioningService.Provision(
				c.Ctx.Request.Context(),
				userCertificateProvisioningInput(cParams),
				c.lifecycleActor(),
			)
			if err != nil {
				logs.Error("ERR_USER_CERTIFICATE_PROVISION")
				key := c.provisioningErrorKey(err)
				c.FlashError(
					flash,
					key,
					"ERR_USER_CERTIFICATE_PROVISION",
					err,
					false,
				)
			} else {
				c.FlashSuccess(
					flash,
					"certificate.provisioned",
					result.CertificateName,
				)
			}
			flash.Store(&c.Controller)
		}
	}
	cfg := models.EasyRSAConfig{Profile: "default"}
	_ = cfg.Read("Profile")
	c.Data["EasyRSA"] = &cfg

	c.Data["ShowArchived"] = false
	c.showCerts()
}

// @router /certificates/:id/revoke [post]
func (c *CertificatesController) Revoke() {
	if !c.ValidSessionCSRF() {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionRevoke,
			c.GetString(":id"),
			"failed",
			"csrf_invalid",
		)
		c.renderCertificateHTTPError(http.StatusForbidden, "error.csrf_invalid")
		return
	}
	if !c.canManageCertificates() {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionRevoke,
			c.GetString(":id"),
			"failed",
			"permission_denied",
		)
		c.renderCertificateHTTPError(http.StatusForbidden, "error.admin_required")
		return
	}
	flash := web.NewFlash()
	certificateID, err := c.certificateID()
	if err != nil || c.LifecycleService == nil {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionRevoke,
			c.GetString(":id"),
			"failed",
			"invalid_target",
		)
		c.FlashError(
			flash,
			"certificate.not_found",
			"ERR_CERT_NOT_FOUND",
			services.ErrCertificateNotFound,
			false,
		)
		flash.Store(&c.Controller)
		c.Redirect(c.URLFor("CertificatesController.Get"), http.StatusSeeOther)
		return
	}

	result, err := c.LifecycleService.RevokeCertificate(
		c.Ctx.Request.Context(),
		certificateID,
		c.GetString("confirmation"),
		c.lifecycleActor(),
	)
	if err != nil {
		logs.Error("ERR_CERT_REVOKE")
		c.FlashError(
			flash,
			c.lifecycleErrorKey(err, "certificate.revoke_failed"),
			"ERR_CERT_REVOKE",
			err,
			false,
		)
	} else if result.AlreadyRevoked {
		c.FlashWarning(flash, "certificate.already_revoked")
	} else if result.DisconnectFailed {
		c.FlashWarning(flash, "certificate.revoked_disconnect_failed")
	} else {
		c.FlashSuccess(flash, "certificate.revoke_completed")
	}
	flash.Store(&c.Controller)
	c.Redirect(c.URLFor("CertificatesController.Get"), http.StatusSeeOther)
}

// @router /certificates/restart [post]
func (c *CertificatesController) Restart() {
	if !c.ValidSessionCSRF() {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionRestart,
			"openvpn",
			"failed",
			"csrf_invalid",
		)
		c.renderCertificateHTTPError(http.StatusForbidden, "error.csrf_invalid")
		return
	}
	if !c.canManageCertificates() {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionRestart,
			"openvpn",
			"failed",
			"permission_denied",
		)
		c.renderCertificateHTTPError(http.StatusForbidden, "error.admin_required")
		return
	}
	if err := c.writeCertificateOperationAudit(
		services.CertificateAuditActionRestart,
		"openvpn",
		services.CertificateAuditResultStarted,
		"",
	); err != nil {
		logs.Error("ERR_CERT_AUDIT_WRITE")
		c.renderCertificateHTTPError(
			http.StatusServiceUnavailable,
			"error.audit_unavailable",
		)
		return
	}
	flash := web.NewFlash()
	if err := lib.Restart(); err != nil {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionRestart,
			"openvpn",
			"failed",
			"restart_failed",
		)
		logs.Error("ERR_OPENVPN_RESTART")
		c.FlashError(flash, "maintenance.restart_failed", "ERR_OPENVPN_RESTART", err, false)
	} else {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionRestart,
			"openvpn",
			"success",
			"",
		)
		c.FlashSuccess(flash, "maintenance.restarted", "OpenVPN")
	}
	flash.Store(&c.Controller)
	c.Redirect(c.URLFor("CertificatesController.Get"), http.StatusSeeOther)
}

// @router /certificates/reload [post]
func (c *CertificatesController) Reload() {
	if !c.ValidSessionCSRF() {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionReload,
			"openvpn",
			"failed",
			"csrf_invalid",
		)
		c.renderCertificateHTTPError(http.StatusForbidden, "error.csrf_invalid")
		return
	}
	if !c.canManageCertificates() {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionReload,
			"openvpn",
			"failed",
			"permission_denied",
		)
		c.renderCertificateHTTPError(http.StatusForbidden, "error.admin_required")
		return
	}
	if err := c.writeCertificateOperationAudit(
		services.CertificateAuditActionReload,
		"openvpn",
		services.CertificateAuditResultStarted,
		"",
	); err != nil {
		logs.Error("ERR_CERT_AUDIT_WRITE")
		c.renderCertificateHTTPError(
			http.StatusServiceUnavailable,
			"error.audit_unavailable",
		)
		return
	}
	flash := web.NewFlash()
	client := mi.NewClient(state.GlobalCfg.MINetwork, state.GlobalCfg.MIAddress)
	if err := client.Signal("SIGUSR1"); err != nil {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionReload,
			"openvpn",
			"failed",
			"reload_failed",
		)
		logs.Error("ERR_OPENVPN_RELOAD")
		c.FlashError(flash, "maintenance.restart_failed", "ERR_OPENVPN_RELOAD", err, false)
	} else {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionReload,
			"openvpn",
			"success",
			"",
		)
		c.FlashSuccess(flash, "maintenance.restarted", "OpenVPN")
	}
	flash.Store(&c.Controller)
	c.Redirect(c.URLFor("CertificatesController.Get"), http.StatusSeeOther)
}

// @router /certificates/:id/archive [post]
func (c *CertificatesController) Archive() {
	if !c.ValidSessionCSRF() {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionArchive,
			c.GetString(":id"),
			"failed",
			"csrf_invalid",
		)
		c.renderCertificateHTTPError(http.StatusForbidden, "error.csrf_invalid")
		return
	}
	if !c.canManageCertificates() {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionArchive,
			c.GetString(":id"),
			"failed",
			"permission_denied",
		)
		c.renderCertificateHTTPError(http.StatusForbidden, "error.admin_required")
		return
	}
	flash := web.NewFlash()
	certificateID, err := c.certificateID()
	if err != nil || c.LifecycleService == nil {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionArchive,
			c.GetString(":id"),
			"failed",
			"invalid_target",
		)
		c.FlashError(
			flash,
			"certificate.not_found",
			"ERR_CERT_NOT_FOUND",
			services.ErrCertificateNotFound,
			false,
		)
		flash.Store(&c.Controller)
		c.Redirect(c.URLFor("CertificatesController.Get"), http.StatusSeeOther)
		return
	}
	result, err := c.LifecycleService.ArchiveCertificate(
		c.Ctx.Request.Context(),
		certificateID,
		c.lifecycleActor(),
	)
	if err != nil {
		logs.Error("ERR_CERT_ARCHIVE")
		c.FlashError(
			flash,
			c.lifecycleErrorKey(err, "certificate.archive_failed"),
			"ERR_CERT_ARCHIVE",
			err,
			false,
		)
	} else if result.AlreadyArchived {
		c.FlashWarning(flash, "certificate.already_archived")
	} else {
		c.FlashSuccess(flash, "certificate.archived")
	}
	flash.Store(&c.Controller)
	c.Redirect(c.URLFor("CertificatesController.Get"), http.StatusSeeOther)
}

// @router /certificates/:id/renew [post]
func (c *CertificatesController) Renew() {
	if !c.ValidSessionCSRF() {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionRenew,
			c.GetString(":id"),
			"failed",
			"csrf_invalid",
		)
		c.renderCertificateHTTPError(http.StatusForbidden, "error.csrf_invalid")
		return
	}
	if !c.canManageCertificates() {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionRenew,
			c.GetString(":id"),
			"failed",
			"permission_denied",
		)
		c.renderCertificateHTTPError(http.StatusForbidden, "error.admin_required")
		return
	}
	flash := web.NewFlash()
	certificateID, err := c.certificateID()
	if err != nil || c.LifecycleService == nil {
		c.recordCertificateOperationAudit(
			services.CertificateAuditActionRenew,
			c.GetString(":id"),
			"failed",
			"invalid_target",
		)
		c.FlashError(
			flash,
			"certificate.not_found",
			"ERR_CERT_NOT_FOUND",
			services.ErrCertificateNotFound,
			false,
		)
	} else {
		result, renewErr := c.LifecycleService.RenewCertificate(
			c.Ctx.Request.Context(),
			certificateID,
			c.lifecycleActor(),
		)
		if renewErr != nil {
			logs.Error("ERR_CERT_RENEW")
			c.FlashError(
				flash,
				c.lifecycleErrorKey(renewErr, "certificate.renew_failed"),
				"ERR_CERT_RENEW",
				renewErr,
				false,
			)
		} else if result.AlreadyRenewed {
			c.FlashWarning(flash, "certificate.already_renewed")
		} else {
			localIP := result.StaticIP
			if localIP == "" {
				localIP = "dynamic.pool"
			}
			c.FlashSuccess(
				flash,
				"certificate.renewed",
				result.CommonName,
				localIP,
				result.PreviousSerial,
			)
		}
	}
	flash.Store(&c.Controller)
	c.Redirect(c.URLFor("CertificatesController.Get"), http.StatusSeeOther)
}

func validateCertParams(cert NewCertParams, localizer *i18n.Localizer) map[string]map[string]string {
	valid := validation.Validation{}
	b, err := valid.Valid(&cert)
	if err != nil {
		logs.Error(err)
		return nil
	}
	if !b {
		return lib.CreateValidationMap(valid, localizer)
	}
	if err := lib.ValidateCertificateCreationRequest(
		certificateCreationRequest(cert),
	); err != nil {
		valid.SetError("Name", "invalid certificate input")
		return lib.CreateValidationMap(valid, localizer)
	}
	return nil
}

func certificateCreationRequest(cert NewCertParams) lib.CertificateCreationRequest {
	return lib.CertificateCreationRequest{
		Name:       cert.Name,
		Passphrase: cert.Passphrase,
		ExpireDays: cert.ExpireDays,
		Email:      cert.Email,
		Country:    cert.Country,
		Province:   cert.Province,
		City:       cert.City,
		Org:        cert.Org,
		OrgUnit:    cert.OrgUnit,
		TFAName:    cert.TFAName,
		TFAIssuer:  cert.TFAIssuer,
	}
}

func userCertificateProvisioningInput(
	cert NewCertParams,
) services.UserCertificateProvisioningInput {
	return services.UserCertificateProvisioningInput{
		DisplayName:     cert.DisplayName,
		Username:        cert.Username,
		Email:           cert.Email,
		Department:      cert.Department,
		CertificateName: cert.Name,
		TFAName:         cert.TFAName,
		TFAIssuer:       cert.TFAIssuer,
		PermissionType:  cert.PermissionType,
		ExpireDays:      cert.ExpireDays,
		DeviceNote:      cert.DeviceNote,
		BusinessNote:    cert.BusinessNote,
		Passphrase:      cert.Passphrase,
		Country:         cert.Country,
		Province:        cert.Province,
		City:            cert.City,
		Org:             cert.Org,
		OrgUnit:         cert.OrgUnit,
	}
}

func (c *CertificatesController) provisioningErrorKey(err error) string {
	switch {
	case errors.Is(err, services.ErrUserProvisioningForbidden):
		return "error.admin_required"
	case errors.Is(err, services.ErrUserProvisioningInvalidInput):
		return "certificate.provision_invalid"
	case errors.Is(err, services.ErrUserProvisioningRecoveryRequired):
		return "certificate.provision_recovery_required"
	case errors.Is(err, services.ErrUserProvisioningAuditUnavailable):
		return "error.audit_unavailable"
	case errors.Is(err, services.ErrRestrictedIPPoolExhausted):
		return "certificate.restricted_pool_exhausted"
	case errors.Is(err, services.ErrRestrictedIPDataSource):
		return "certificate.restricted_source_unavailable"
	case errors.Is(err, services.ErrUserProvisioningConflict),
		errors.Is(err, services.ErrRestrictedIPConflict),
		errors.Is(err, lib.ErrCertificateAlreadyExists):
		return "certificate.provision_conflict"
	default:
		return "certificate.create_failed"
	}
}

func (c *CertificatesController) certificateID() (int64, error) {
	certificateID, err := strconv.ParseInt(c.GetString(":id"), 10, 64)
	if err != nil || certificateID <= 0 {
		return 0, services.ErrCertificateNotFound
	}
	return certificateID, nil
}

func (c *CertificatesController) canManageCertificates() bool {
	return c.Userinfo != nil && c.Userinfo.IsAdmin
}

func (c *CertificatesController) lifecycleActor() services.CertificateLifecycleActor {
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

func (c *CertificatesController) recordCertificateOperationAudit(
	action string,
	targetID string,
	result string,
	errorSummary string,
) {
	if err := c.writeCertificateOperationAudit(
		action,
		targetID,
		result,
		errorSummary,
	); err != nil {
		logs.Error("ERR_CERT_AUDIT_WRITE")
	}
}

func (c *CertificatesController) writeCertificateOperationAudit(
	action string,
	targetID string,
	result string,
	errorSummary string,
) error {
	if c.LifecycleService == nil {
		return errors.New("certificate lifecycle service is unavailable")
	}
	return c.LifecycleService.RecordCertificateOperationAudit(
		c.Ctx.Request.Context(),
		c.lifecycleActor(),
		action,
		targetID,
		result,
		errorSummary,
	)
}

func (c *CertificatesController) lifecycleErrorKey(err error, fallback string) string {
	switch {
	case errors.Is(err, services.ErrCertificateForbidden):
		return "error.admin_required"
	case errors.Is(err, services.ErrCertificateNotFound):
		return "certificate.not_found"
	case errors.Is(err, services.ErrCertificateConfirmation):
		return "certificate.confirmation_mismatch"
	case errors.Is(err, services.ErrCertificateInvalidState):
		return "certificate.invalid_state"
	case errors.Is(err, services.ErrCertificateIdentity),
		errors.Is(err, services.ErrCertificatePKIMismatch):
		return "certificate.identity_invalid"
	case errors.Is(err, services.ErrCertificateIndexCompatibility):
		return "certificate.legacy_index_incompatible"
	default:
		return fallback
	}
}

func (c *CertificatesController) renderCertificateHTTPError(status int, key string) {
	c.Ctx.Output.SetStatus(status)
	c.Ctx.Output.Header("Content-Type", "text/plain; charset=utf-8")
	c.Ctx.Output.Body([]byte(c.T(key)))
}

func (c *CertificatesController) saveClientConfig(keysPath string, name string) (string, error) {
	if !services.ValidateCertificateCommonName(name) {
		return "", services.ErrCertificateIdentity
	}
	cfg := clientconfig.New()
	keysPathCa := filepath.Join(state.GlobalCfg.OVConfigPath, "pki")

	ovClientConfig := &models.OVClientConfig{Profile: "default"}
	if err := ovClientConfig.Read("Profile"); err != nil {
		return "", err
	}
	cfg.ServerAddress = ovClientConfig.ServerAddress
	cfg.OpenVpnServerPort = ovClientConfig.OpenVpnServerPort
	cfg.AuthUserPass = ovClientConfig.AuthUserPass
	cfg.ResolveRetry = ovClientConfig.ResolveRetry
	cfg.OVClientUser = ovClientConfig.OVClientUser
	cfg.OVClientGroup = ovClientConfig.OVClientGroup
	cfg.PersistTun = ovClientConfig.PersistTun
	cfg.PersistKey = ovClientConfig.PersistKey
	cfg.RemoteCertTLS = ovClientConfig.RemoteCertTLS
	cfg.RedirectGateway = ovClientConfig.RedirectGateway
	cfg.Proto = ovClientConfig.Proto   // this will be set from client instead of server config
	cfg.Auth = ovClientConfig.Auth     // this will be set from client instead of server config
	cfg.Cipher = ovClientConfig.Cipher // this will be set from client instead of server config
	cfg.Device = ovClientConfig.Device
	cfg.AuthNoCache = ovClientConfig.AuthNoCache
	cfg.TlsClient = ovClientConfig.TlsClient
	cfg.Verbose = ovClientConfig.Verbose
	cfg.CustomConfOne = ovClientConfig.CustomConfOne
	cfg.CustomConfTwo = ovClientConfig.CustomConfTwo
	cfg.CustomConfThree = ovClientConfig.CustomConfThree

	ca, err := os.ReadFile(filepath.Join(keysPathCa, "ca.crt"))
	if err != nil {
		return "", err
	}
	cfg.Ca = string(ca)

	ta, err := os.ReadFile(filepath.Join(keysPathCa, "ta.key"))
	if err != nil {
		return "", err
	}
	cfg.Ta = string(ta)

	cert, err := os.ReadFile(filepath.Join(keysPath, name+".crt"))
	if err != nil {
		return "", err
	}
	cfg.Cert = string(cert)

	keysPathKey := filepath.Join(state.GlobalCfg.OVConfigPath, "pki/private")
	key, err := os.ReadFile(filepath.Join(keysPathKey, name+".key"))
	if err != nil {
		return "", err
	}
	cfg.Key = string(key)

	serverConfig := models.OVConfig{Profile: "default"}
	_ = serverConfig.Read("Profile")
	cfg.Port = serverConfig.Port
	// cfg.Proto = serverConfig.Proto   //Now getting it from client config
	// cfg.Auth = serverConfig.Auth     //Now getting it from client config
	// cfg.Cipher = serverConfig.Cipher //Now getting it from client config

	destPath := filepath.Join(state.GlobalCfg.OVConfigPath, "clients", name+".ovpn")
	if err := SaveToFile(filepath.Join(c.ConfigDir, "openvpn-client-config.tpl"), cfg, destPath); err != nil {
		logs.Error("ERR_CERT_CONFIG_WRITE")
		return "", err
	}

	return destPath, nil
}

func GetText(tpl string, c clientconfig.Config) (string, error) {
	t := template.New("config")
	t, err := t.Parse(tpl)
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	err = t.Execute(buf, c)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func SaveToFile(tplPath string, c clientconfig.Config, destPath string) error {
	tpl, err := os.ReadFile(tplPath)
	if err != nil {
		return err
	}

	str, err := GetText(string(tpl), c)
	if err != nil {
		return err
	}

	destinationDirectory := filepath.Dir(destPath)
	temporaryFile, err := os.CreateTemp(destinationDirectory, ".ovpn-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporaryFile.Name()
	defer os.Remove(temporaryPath)

	if err := temporaryFile.Chmod(0o600); err != nil {
		temporaryFile.Close()
		return err
	}
	if _, err := temporaryFile.WriteString(str); err != nil {
		temporaryFile.Close()
		return err
	}
	if err := temporaryFile.Sync(); err != nil {
		temporaryFile.Close()
		return err
	}
	if err := temporaryFile.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, destPath)
}
