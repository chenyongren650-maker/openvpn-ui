package controllers

import (
	"html/template"

	passlib "gopkg.in/hlandau/passlib.v1"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/core/validation"
	"github.com/beego/beego/v2/server/web"
	"github.com/d3vilh/openvpn-ui/i18n"
	"github.com/d3vilh/openvpn-ui/lib"
	"github.com/d3vilh/openvpn-ui/models"
)

type NewUser struct {
	NewLogin      string `orm:"size(64);unique" form:"NewLogin" valid:"Required;"`
	NewName       string `orm:"size(64);unique" form:"NewName" valid:"Required;"`
	NewIsAdmin    bool   `orm:"default(false)" form:"IsAdmin" valid:"Required;"`
	NewEmail      string `orm:"size(64)" form:"NewEmail" valid:"Required;Email"`
	NewPassword   string `orm:"size(32)" form:"NewPassword" valid:"Required;MinSize(6)"`
	NewRepassword string `orm:"-" form:"NewRepassword" valid:"Required"`
}

type ProfileController struct {
	BaseController
}

func (c *ProfileController) NestPrepare() {
	if !c.IsLogin {
		c.Ctx.Redirect(302, c.LoginPath())
		return
	}
	c.Data["breadcrumbs"] = &BreadCrumbs{
		Title: c.T("breadcrumb.profile"),
	}
}

func (c *ProfileController) Get() {
	c.Data["xsrfdata"] = template.HTML(c.XSRFFormHTML())
	c.Data["profile"] = c.Userinfo
	c.TplName = "profile.html"

	// Get all users if user has admin flag - show all users
	if c.Userinfo.IsAdmin {
		o := orm.NewOrm()
		var users []*models.User
		if _, err := o.QueryTable("user").All(&users); err != nil {
			logs.Error("Failed to retrieve user profiles:", err)
			return
		}
		//logs.Info("Retrieved", len(users), "user profiles")
		c.Data["users"] = users
	}
}

func (c *ProfileController) Post() {
	c.TplName = "profile.html"
	c.Data["profile"] = c.Userinfo

	flash := web.NewFlash()

	user := models.User{}
	if err := c.ParseForm(&user); err != nil {
		logs.Error("ERR_PROFILE_FORM")
		c.FlashError(flash, "error.form_parse", "ERR_PROFILE_FORM", err, false)
		flash.Store(&c.Controller)
		return
	}
	user.Login = c.Userinfo.Login
	c.Data["profile"] = user

	if vMap := validateUser(user, c.Localizer); vMap != nil {
		c.Data["validation"] = vMap
		c.List()
		return
	}

	hash, err := passlib.Hash(user.Password)
	if err != nil {
		c.FlashError(flash, "profile.password_hash_failed", "ERR_PASSWORD_HASH", err, false)
		flash.Store(&c.Controller)
		return
	}
	c.Userinfo.Email = user.Email
	c.Userinfo.Name = user.Name
	c.Userinfo.Password = hash
	o := orm.NewOrm()
	if _, err := o.Update(c.Userinfo); err != nil {
		c.FlashError(flash, "error.database_update", "ERR_PROFILE_DB", err, false)
	} else {
		c.FlashSuccess(flash, "profile.updated")
	}
	flash.Store(&c.Controller)
	c.List()
}

func validateUser(user models.User, localizer *i18n.Localizer) map[string]map[string]string {
	valid := validation.Validation{}
	b, err := valid.Valid(&user)
	if err != nil {
		logs.Error(err)
		return nil
	}
	if !b {
		return lib.CreateValidationMap(valid, localizer)
	}
	return nil
}

func validateNewUser(nuser NewUser, localizer *i18n.Localizer) map[string]map[string]string {
	valid := validation.Validation{}
	b, err := valid.Valid(&nuser)
	if err != nil {
		logs.Error(err)
		return nil
	}
	if !b {
		return lib.CreateValidationMap(valid, localizer)
	}
	return nil
}

// @router /profile/create [Create]
func (c *ProfileController) Create() {
	c.TplName = "profile.html"
	c.Data["profile"] = c.Userinfo
	flash := web.NewFlash()
	user := models.User{
		Login:      c.GetString("NewLogin"),
		Name:       c.GetString("NewName"),
		Email:      c.GetString("NewEmail"),
		Password:   c.GetString("NewPassword"),
		Repassword: c.GetString("NewRepassword"),
		IsAdmin:    c.GetString("NewIsAdmin") == "on",
	}

	uParams := NewUser{
		NewLogin:      c.GetString("NewLogin"),
		NewName:       c.GetString("NewName"),
		NewEmail:      c.GetString("NewEmail"),
		NewPassword:   c.GetString("NewPassword"),
		NewRepassword: c.GetString("NewRepassword"),
		NewIsAdmin:    c.GetString("NewIsAdmin") == "on",
	}

	if err := c.ParseForm(&user); err != nil {
		logs.Error("ERR_USER_FORM")
		c.FlashError(flash, "error.form_parse", "ERR_USER_FORM", err, false)
		flash.Store(&c.Controller)
		return
	}

	if vMap := validateNewUser(uParams, c.Localizer); vMap != nil {
		c.Data["validation"] = vMap
		c.List()
		return
	}

	o := orm.NewOrm()
	var existingUser models.User
	err := o.QueryTable("user").Filter("Login", user.Login).One(&existingUser)
	if err == nil {
		c.FlashWarning(flash, "profile.user_exists", user.Login)
		flash.Store(&c.Controller)
		logs.Info("User already exists:", user.Login)
		c.List()
		return
	} else if err != orm.ErrNoRows {
		logs.Error(err)
		c.FlashError(flash, "error.database_read", "ERR_USER_LOOKUP", err, false)
		flash.Store(&c.Controller)
		return
	}

	var lastUser models.User
	err1 := o.QueryTable("user").OrderBy("-id").One(&lastUser)
	if err1 == orm.ErrNoRows {
		lastUser.Id = 0
	} else if err1 != nil {
		logs.Error(err1)
		c.FlashError(flash, "error.database_read", "ERR_USER_SEQUENCE", err1, false)
		flash.Store(&c.Controller)
		return
	}
	newUser := models.User{
		Id:       lastUser.Id + 1,
		Login:    user.Login,
		IsAdmin:  user.IsAdmin,
		Name:     user.Name,
		Email:    user.Email,
		Password: user.Password,
	}
	hash, err := passlib.Hash(newUser.Password)
	if err != nil {
		logs.Error("ERR_PASSWORD_HASH")
		c.FlashError(flash, "profile.password_hash_failed", "ERR_PASSWORD_HASH", err, false)
		flash.Store(&c.Controller)
		return
	}
	newUser.Password = hash
	if created, _, err := o.ReadOrCreate(&newUser, "Name"); err == nil {
		if created {
			logs.Info("New user with login \"" + user.Login + "\" created successfully.")
			c.FlashSuccess(flash, "profile.user_created", user.Login)
			flash.Store(&c.Controller)
		} else {
			logs.Debug("Admin account already exists")
		}
	} else {
		logs.Error(err)
		c.FlashError(flash, "profile.user_create_failed", "ERR_USER_CREATE", err, false)
	}

	flash.Store(&c.Controller)
	c.List()
}

// @router /profile [post]
func (c *ProfileController) List() {
	o := orm.NewOrm()
	var users []*models.User
	if _, err := o.QueryTable("user").All(&users); err != nil {
		logs.Error("Failed to retrieve user profiles:", err)
		return
	}
	//logs.Info("Retrieved", len(users), "user profiles")
	c.Data["users"] = users
	c.TplName = "profile.html"
}

// @router /profile/delete/:key [get]
func (c *ProfileController) DeleteUser() {
	c.TplName = "profile.html"
	flash := web.NewFlash()
	id, err := c.GetInt(":key")
	if err != nil {
		logs.Error("Failed to get user ID:", err)
		c.FlashError(flash, "profile.invalid_user", "ERR_USER_ID", err, false)
		flash.Store(&c.Controller)
		return
	}

	o := orm.NewOrm()
	user := models.User{Id: int64(id)}

	// Read the user first to populate the Login field before deleting it from the database
	err = o.Read(&user)
	if err != nil {
		logs.Error("Failed to get user:", err)
		c.FlashError(flash, "profile.user_read_failed", "ERR_USER_READ", err, false)
		flash.Store(&c.Controller)
		return
	}

	if _, err := o.Delete(&user); err != nil {
		logs.Error("Failed to delete user \""+user.Login+"\" profile:", err)
		c.FlashError(flash, "profile.user_delete_failed", "ERR_USER_DELETE", err, false)
		flash.Store(&c.Controller)
		return
	}

	logs.Info("New user with login \""+user.Login+"\" deleted successfully. It had user ID: ", id)
	c.FlashSuccess(flash, "profile.user_deleted", user.Login)
	flash.Store(&c.Controller)
	c.List()
}

// @router /profile/edit/:key [post]
func (c *ProfileController) EditUser() {
	c.TplName = "profile.html"
	flash := web.NewFlash()
	id, err := c.GetInt(":key")
	if err != nil {
		logs.Error("Failed to get user ID:", err)
		c.FlashError(flash, "profile.invalid_user", "ERR_USER_ID", err, false)
		flash.Store(&c.Controller)
		return
	}

	o := orm.NewOrm()
	user := models.User{Id: int64(id)}
	if err := o.Read(&user); err != nil {
		logs.Error("Failed to read user \""+user.Name+"\" profile:", err)
		c.FlashError(flash, "profile.user_read_failed", "ERR_USER_READ", err, false)
		flash.Store(&c.Controller)
		return
	}

	// Updating form "username" and "email" fields
	username := c.GetString("name")
	email := c.GetString("email")

	user.Name = username
	user.Email = email

	if username != "" {
		user.Name = username
	}
	if email != "" {
		user.Email = email
	}

	if _, err := o.Update(&user); err != nil {
		logs.Error("Failed to update user \""+user.Name+"\" profile:", err)
		c.FlashError(flash, "profile.user_update_failed", "ERR_USER_UPDATE", err, false)
		flash.Store(&c.Controller)
		return
	}

	logs.Info("Updated user profile with ID", id)
	c.FlashSuccess(flash, "profile.user_updated", user.Name)
	flash.Store(&c.Controller)
	c.List()
}
