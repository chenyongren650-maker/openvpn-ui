package controllers

import (
	"github.com/beego/beego/v2/server/web"
	"github.com/d3vilh/openvpn-ui/i18n"
	"github.com/d3vilh/openvpn-ui/models"
)

const languageCookieMaxAge = 365 * 24 * 60 * 60

type BaseController struct {
	web.Controller

	Userinfo  *models.User
	IsLogin   bool
	Localizer *i18n.Localizer
}

type languageCookieSettings struct {
	MaxAge   int
	Path     string
	Secure   bool
	HTTPOnly bool
	SameSite string
}

type NestPreparer interface {
	NestPrepare()
}

type NestFinisher interface {
	NestFinish()
}

func (c *BaseController) Prepare() {
	c.Ctx.Output.Header("Cache-Control", "no-store, no-cache, must-revalidate, private")
	c.Ctx.Output.Header("Pragma", "no-cache")
	c.Ctx.Output.Header("Expires", "0")
	c.SetParams()
	c.prepareLanguage()

	userID := c.GetSession("userinfo")
	if userID != nil {
		var user models.User
		user.Id = userID.(int64)
		err := user.Read("Id")
		if err == nil {
			c.IsLogin = true
			c.Userinfo = &user
		} else {
			c.IsLogin = false
			c.DelSession("userinfo")
		}
	} else {
		c.IsLogin = false
	}

	c.Data["IsLogin"] = c.IsLogin
	c.Data["Userinfo"] = c.Userinfo

	if app, ok := c.AppController.(NestPreparer); ok {
		app.NestPrepare()
	}
}

func (c *BaseController) prepareLanguage() {
	queryLanguage := c.GetString("lang")
	cookieLanguage := c.Ctx.GetCookie(i18n.CookieName)
	language, cookieSettings := resolveLanguagePreference(queryLanguage, cookieLanguage, c.Ctx.Input.IsSecure())
	if cookieSettings != nil {
		c.Ctx.SetCookie(
			i18n.CookieName,
			language,
			cookieSettings.MaxAge,
			cookieSettings.Path,
			"",
			cookieSettings.Secure,
			cookieSettings.HTTPOnly,
			cookieSettings.SameSite,
		)
	}

	c.Localizer = i18n.NewLocalizer(language)
	c.Data["Localizer"] = c.Localizer
	c.Data["Language"] = language
	c.Data["LanguageURLZhCN"] = i18n.LanguageURL(c.Ctx.Request.URL, i18n.DefaultLanguage)
	c.Data["LanguageURLEnUS"] = i18n.LanguageURL(c.Ctx.Request.URL, i18n.EnglishLanguage)
}

func resolveLanguagePreference(queryLanguage, cookieLanguage string, secure bool) (string, *languageCookieSettings) {
	language := i18n.ResolveLanguage(queryLanguage, cookieLanguage)
	if !i18n.IsSupported(queryLanguage) {
		return language, nil
	}
	return language, &languageCookieSettings{
		MaxAge:   languageCookieMaxAge,
		Path:     "/",
		Secure:   secure,
		HTTPOnly: true,
		SameSite: "Lax",
	}
}

// T returns a translated user-facing message for the current request.
func (c *BaseController) T(key string, args ...interface{}) string {
	if c.Localizer == nil {
		return key
	}
	return c.Localizer.T(key, args...)
}

func (c *BaseController) Finish() {
	if app, ok := c.AppController.(NestFinisher); ok {
		app.NestFinish()
	}
}

func (c *BaseController) GetLogin() *models.User {
	u := &models.User{Id: c.GetSession("userinfo").(int64)}
	u.Read("Id")
	return u
}

func (c *BaseController) DelLogin() {
	c.DelSession("userinfo")
	c.IsLogin = false
	c.Userinfo = nil
}

func (c *BaseController) SetLogin(user *models.User) {
	c.SetSession("userinfo", user.Id)
	c.IsLogin = true
	c.Userinfo = user
}

func (c *BaseController) LoginPath() string {
	return c.URLFor("LoginController.Login")
}

func (c *BaseController) SetParams() {
	c.Data["Params"] = make(map[string]string)
	input, err := c.Input()
	if err != nil {
		// handle the error
		// log.Println("Error getting input:", err)
		return
	}
	for k, v := range input {
		c.Data["Params"].(map[string]string)[k] = v[0]
	}
}

type BreadCrumbs struct {
	Title    string
	Subtitle string
}
