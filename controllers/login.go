package controllers

import (
	"context"
	"html/template"
	"log"
	"os"
	"strings"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
	"github.com/d3vilh/openvpn-ui/lib"
	"github.com/d3vilh/openvpn-ui/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	oauth2api "google.golang.org/api/oauth2/v2"
)

// Initialize OAuth2 configuration
var (
	oauthConf        *oauth2.Config
	oauthStateString = "random" // use a random string for security purposes
	allowedDomains   []string
)

func init() {
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	redirectURL := os.Getenv("GOOGLE_REDIRECT_URL")
	allowedDomainsStr := os.Getenv("ALLOWED_DOMAINS")

	if clientID == "" {
		log.Println("Environment variable GOOGLE_CLIENT_ID not set")
	}
	if clientSecret == "" {
		log.Println("Environment variable GOOGLE_CLIENT_SECRET not set")
	}
	if redirectURL == "" {
		log.Println("Environment variable GOOGLE_REDIRECT_URL not set")
	}
	if allowedDomainsStr == "" {
		log.Println("Environment variable ALLOWED_DOMAINS not set")
	}
	oauthConf = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	if allowedDomainsStr != "" {
		allowedDomains = strings.Split(allowedDomainsStr, ",")
	} else {
		allowedDomains = []string{}
	}
}

type LoginController struct {
	BaseController
}

func (c *LoginController) Login() {
	if c.IsLogin {
		c.Ctx.Redirect(302, c.URLFor("MainController.Get"))
		return
	}

	c.TplName = "login.html"
	c.Data["xsrfdata"] = template.HTML(c.XSRFFormHTML())
	if !c.Ctx.Input.IsPost() {
		return
	}

	flash := web.NewFlash()
	login := c.GetString("login")
	password := c.GetString("password")

	authType, err := web.AppConfig.String("AuthType")
	if err != nil {
		c.setLoginError("login.configuration_error", "ERR_LOGIN_CONFIG")
		return
	}
	user, err := lib.Authenticate(login, password, authType)

	if err != nil {
		c.setLoginError("login.invalid_credentials", "ERR_LOGIN_FAILED")
		return
	}
	user.Lastlogintime = time.Now()
	err = user.Update("Lastlogintime")
	if err != nil {
		c.setLoginError("login.update_failed", "ERR_LOGIN_UPDATE")
		return
	}
	c.FlashSuccess(flash, "login.success")
	flash.Store(&c.Controller)

	c.SetLogin(user)

	c.Redirect(c.URLFor("MainController.Get"), 303)
}

func (c *LoginController) Logout() {
	c.DelLogin()
	flash := web.NewFlash()
	c.FlashSuccess(flash, "logout.success")
	flash.Store(&c.Controller)

	c.Ctx.Redirect(302, c.URLFor("LoginController.Login"))
}

func (c *LoginController) GoogleLogin() {
	url := oauthConf.AuthCodeURL(oauthStateString)
	c.Redirect(url, 302)
}

func (c *LoginController) GoogleCallback() {
	state := c.GetString("state")
	if state != oauthStateString {
		c.renderLoginError("oauth.invalid_state", "ERR_OAUTH_STATE")
		return
	}

	code := c.GetString("code")
	token, err := oauthConf.Exchange(context.Background(), code)
	if err != nil {
		c.renderLoginError("oauth.exchange_failed", "ERR_OAUTH_EXCHANGE")
		return
	}

	client := oauthConf.Client(context.Background(), token)
	service, err := oauth2api.New(client)
	if err != nil {
		c.renderLoginError("oauth.service_failed", "ERR_OAUTH_SERVICE")
		return
	}

	userinfo, err := service.Userinfo.Get().Do()
	if err != nil {
		c.renderLoginError("oauth.userinfo_failed", "ERR_OAUTH_USERINFO")
		return
	}

	logs.Info("User Info: %+v", userinfo)

	// Check if the user's email domain is allowed
	emailDomain := strings.Split(userinfo.Email, "@")[1]
	allowed := false
	for _, domain := range allowedDomains {
		if emailDomain == domain {
			allowed = true
			break
		}
	}

	if !allowed {
		c.renderLoginError("oauth.email_not_allowed", "ERR_OAUTH_EMAIL_DENIED")
		return
	}

	user, err := lib.GetUserByEmail(userinfo.Email)
	if err != nil {
		if err.Error() == "user not found" {
			// Create a new user if not found and set the default values
			user = &models.User{
				Email:         userinfo.Email,
				Name:          userinfo.Email, // Set the name to the email address
				Login:         userinfo.Email,
				Lastlogintime: time.Now(),
				Allowed:       true, // Set to true because authenticated with Google
			}
			err = user.Insert()
			if err != nil {
				c.renderLoginError("oauth.user_create_failed", "ERR_OAUTH_USER_CREATE")
				return
			}
		} else {
			c.renderLoginError("oauth.user_read_failed", "ERR_OAUTH_USER_READ")
			return
		}
	} else {
		// Update existing user's allowed status, last login time, and name
		user.Allowed = true
		user.Lastlogintime = time.Now()
		user.Name = userinfo.Email // Set the name to the email address
		err = user.Update("Allowed", "Lastlogintime", "Name")
		if err != nil {
			c.renderLoginError("oauth.user_update_failed", "ERR_OAUTH_USER_UPDATE")
			return
		}
	}

	// Check if the user is allowed
	if !user.Allowed {
		c.renderLoginError("error.access_denied", "ERR_ACCESS_DENIED")
		return
	}

	c.SetLogin(user)

	flash := web.NewFlash()
	c.FlashSuccess(flash, "oauth.login_success")
	flash.Store(&c.Controller)

	c.Redirect(c.URLFor("MainController.Get"), 302)
}

func (c *LoginController) renderLoginError(messageKey, code string) {
	logs.Warning("%s", code)
	c.setLoginError(messageKey, code)
	c.Data["xsrfdata"] = template.HTML(c.XSRFFormHTML())
	if err := c.Render(); err != nil {
		logs.Warning("ERR_LOGIN_RENDER")
	}
}

func (c *LoginController) setLoginError(messageKey, code string) {
	c.Data["error"] = c.T(messageKey)
	c.Data["error_code"] = code
	c.TplName = "login.html"
}
