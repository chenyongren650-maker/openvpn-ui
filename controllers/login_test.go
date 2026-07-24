package controllers

import (
	"path/filepath"
	"testing"

	"github.com/d3vilh/openvpn-ui/i18n"
)

func TestSetLoginErrorPopulatesVisibleTemplateData(t *testing.T) {
	catalog, err := i18n.LoadCatalog(filepath.Join("..", "locales"))
	if err != nil {
		t.Fatalf("load login test translations: %v", err)
	}
	controller := &LoginController{}
	controller.Data = make(map[interface{}]interface{})
	controller.Localizer = catalog.Localizer(i18n.DefaultLanguage)

	controller.setLoginError("login.invalid_credentials", "ERR_LOGIN_FAILED")

	if controller.TplName != "login.html" {
		t.Fatalf("login error template = %q, want login.html", controller.TplName)
	}
	if got := controller.Data["error"]; got != "用户名或密码错误" {
		t.Fatalf("visible login error = %q", got)
	}
	if got := controller.Data["error_code"]; got != "ERR_LOGIN_FAILED" {
		t.Fatalf("login error code = %q", got)
	}
}
