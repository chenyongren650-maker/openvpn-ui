package controllers

import (
	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
	"github.com/d3vilh/openvpn-ui/lib"
)

type DangerController struct {
	BaseController
}

func (c *DangerController) NestPrepare() {
	if !c.IsLogin {
		c.Ctx.Redirect(302, c.LoginPath())
		return
	}
}

func (c *DangerController) Get() {
	c.TplName = "maintenance.html"
	c.Data["breadcrumbs"] = &BreadCrumbs{
		Title: c.T("breadcrumb.maintenance"),
	}
}

// @router /pki/delete/:key [DeletePKI]
func (c *DangerController) DeletePKI() {
	c.TplName = "maintenance.html"
	flash := web.NewFlash()
	name := c.GetString(":key")
	//logs.Info("Controller: Deleting:", name)
	if err := lib.DeletePKI(name); err != nil {
		logs.Error("ERR_MAINTENANCE_DELETE")
		c.FlashError(flash, "maintenance.delete_failed", "ERR_MAINTENANCE_DELETE", err, false)
		flash.Store(&c.Controller)
	} else {
		c.FlashSuccess(flash, "maintenance.deleted", name)
		flash.Store(&c.Controller)
	}
	c.Data["Flash"] = flash.Data
	//logs.Info("Flash message stored:", flash.Data)
	//	c.Redirect(c.URLFor("DangerController.Get"), 302)
}

// @router /pki/init/:key [InitPKI]
func (c *DangerController) InitPKI() {
	c.TplName = "maintenance.html"
	flash := web.NewFlash()
	name := c.GetString(":key")
	//logs.Info("Controller: Runing init for:", name)
	if err := lib.InitPKI(name); err != nil {
		logs.Error("ERR_MAINTENANCE_INIT")
		c.FlashError(flash, "maintenance.initialize_failed", "ERR_MAINTENANCE_INIT", err, false)
		flash.Store(&c.Controller)
	} else {
		c.FlashSuccess(flash, "maintenance.initialized", name)
		flash.Store(&c.Controller)
	}
	c.Data["Flash"] = flash.Data
	//logs.Info("Flash message stored:", flash.Data)
	//	c.Redirect(c.URLFor("DangerController.Get"), 302)
}

// @router /container/restart [RestartContainer]
func (c *DangerController) RestartContainer() {
	c.TplName = "maintenance.html"
	flash := web.NewFlash()
	name := c.GetString(":key")
	//logs.Info("Controller: Restarting:", name)
	if err := lib.RestartContainer(name); err != nil {
		logs.Error("ERR_CONTAINER_RESTART")
		//	logs.Error("Stack trace:", string(debug.Stack()))
		c.FlashError(flash, "maintenance.restart_failed", "ERR_CONTAINER_RESTART", err, false)
		flash.Store(&c.Controller)
	} else {
		c.FlashSuccess(flash, "maintenance.restarted", name)
		flash.Store(&c.Controller)
	}
	c.Data["Flash"] = flash.Data
	//logs.Info("Flash message stored:", flash.Data)
}
