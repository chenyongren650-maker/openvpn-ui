package controllers

import (
	"html/template"
	"os"
	"path/filepath"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
	"github.com/d3vilh/openvpn-server-config/server/config"
	mi "github.com/d3vilh/openvpn-server-config/server/mi"
	"github.com/d3vilh/openvpn-ui/lib"
	"github.com/d3vilh/openvpn-ui/models"
	"github.com/d3vilh/openvpn-ui/state"
)

type OVConfigController struct {
	BaseController
	ConfigDir string
}

func (c *OVConfigController) NestPrepare() {
	if !c.IsLogin {
		c.Ctx.Redirect(302, c.LoginPath())
		return
	}
	c.Data["breadcrumbs"] = &BreadCrumbs{
		Title: c.T("breadcrumb.server_config"),
	}
}

// @router /ov/config [Get]
func (c *OVConfigController) Get() {
	c.TplName = "ovconfig.html"
	besettings := models.Settings{Profile: "default"}
	_ = besettings.Read("Profile")
	c.Data["BeeSettings"] = &besettings
	c.Data["xsrfdata"] = template.HTML(c.XSRFFormHTML())
	cfg := models.OVConfig{Profile: "default"}
	_ = cfg.Read("Profile")
	c.Data["Settings"] = &cfg

	destPath := filepath.Join(state.GlobalCfg.OVConfigPath, "server.conf")
	serverConf, err := os.ReadFile(destPath)
	if err != nil {
		flash := web.NewFlash()
		c.FlashError(flash, "error.file_read", "ERR_SERVER_READ", err, true)
		flash.Store(&c.Controller)
		return
	}
	c.Data["ServerConfig"] = string(serverConf)
}

// @router /ov/config [Post]
func (c *OVConfigController) Post() {
	logs.Info("Starting Post method in OVConfigController")

	c.TplName = "ovconfig.html"
	flash := web.NewFlash()
	cfg := models.OVConfig{Profile: "default"}
	_ = cfg.Read("Profile")

	logs.Info("Post: Parsing form data")
	logs.Info("Form data before parsing: %v", c.Ctx.Request.Form)
	if err := c.ParseForm(&cfg); err != nil {
		logs.Warning(err)
		c.FlashError(flash, "error.form_parse", "ERR_SERVER_FORM", err, true)
		flash.Store(&c.Controller)
		return
	}
	logs.Info("Form data after parsing: %v", c.Ctx.Request.Form)

	logs.Info("Post: Dumping configuration data")
	logs.Info("Configuration data: %v", cfg)
	lib.Dump(cfg)
	c.Data["Settings"] = &cfg
	logs.Info("Settings data: %v", c.Data["Settings"])

	destPath := filepath.Join(state.GlobalCfg.OVConfigPath, "server.conf")
	logs.Info("Post: Saving configuration to file according to template")
	err := config.SaveToFile(filepath.Join(c.ConfigDir, "openvpn-server-config.tpl"), cfg.Config, destPath)
	if err != nil {
		logs.Warning(err)
		c.FlashError(flash, "error.file_write", "ERR_SERVER_WRITE", err, true)
		flash.Store(&c.Controller)
		return
	}

	logs.Info("Post: Updating configuration in database")
	o := orm.NewOrm()
	if _, err := o.Update(&cfg); err != nil {
		c.FlashError(flash, "error.database_update", "ERR_SERVER_DB", err, true)
	} else {
		c.FlashSuccess(flash, "config.updated")
		client := mi.NewClient(state.GlobalCfg.MINetwork, state.GlobalCfg.MIAddress)
		if err := client.Signal("SIGTERM"); err != nil {
			c.FlashWarning(flash, "config.updated_reload_failed")
			flash.Set("warning_code", "ERR_OPENVPN_RELOAD")
		}
	}

	logs.Info("Post: Reading updated server configuration from file")
	serverConf, err := os.ReadFile(destPath)
	if err != nil {
		logs.Error("Error reading server config from file:", err)
		c.FlashError(flash, "error.file_read", "ERR_SERVER_READ", err, true)
		flash.Store(&c.Controller)
		return
	}
	c.Data["ServerConfig"] = string(serverConf)

	flash.Store(&c.Controller)
}

// @router /ov/config/edit [Edit]
func (c *OVConfigController) Edit() {
	c.TplName = "ovconfig.html"
	flash := web.NewFlash()
	cfg := models.OVConfig{Profile: "default"}
	_ = cfg.Read("Profile")

	//logs.Info("Post: Parsing form data")
	if err := c.ParseForm(&cfg); err != nil {
		logs.Warning(err)
		c.FlashError(flash, "error.form_parse", "ERR_SERVER_FORM", err, true)
		flash.Store(&c.Controller)
		return
	}

	//logs.Info("Post: Dumping configuration data")
	lib.Dump(cfg)
	c.Data["Settings"] = &cfg

	//logs.Info("Starting Edit method in OVConfigController")
	destPath := filepath.Join(state.GlobalCfg.OVConfigPath, "server.conf")

	err := lib.ConfSaveToFile(destPath, c.GetString("ServerConfig"))
	if err != nil {
		logs.Error("Error saving server config to file:", err)
		c.FlashError(flash, "error.file_write", "ERR_SERVER_WRITE", err, true)
		flash.Store(&c.Controller)
		return
	} else {
		//logs.Info("Edit: Server config saved to file:", destPath)
		c.FlashSuccess(flash, "config.updated")
	}

	serverConf, err := os.ReadFile(destPath)
	if err != nil {
		logs.Error("Error reading server config from file:", err)
		c.FlashError(flash, "error.file_read", "ERR_SERVER_READ", err, true)
		flash.Store(&c.Controller)
		return
	}
	c.Data["ServerConfig"] = string(serverConf)

	flash.Store(&c.Controller)
}
