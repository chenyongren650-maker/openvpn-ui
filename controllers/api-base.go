package controllers

import (
	"github.com/beego/beego/v2/core/logs"
)

type APIBaseController struct {
	BaseController
}

// JSONResponse http://stackoverflow.com/a/12979961
type JSONResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Code    string      `json:"code,omitempty"`
	Detail  string      `json:"detail,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

func NewJSONResponse() *JSONResponse {
	response := &JSONResponse{
		Status: "success",
	}
	return response
}

func (c *APIBaseController) Prepare() {
	c.EnableXSRF = false
	c.BaseController.Prepare()
}

func (c *APIBaseController) NestPrepare() {
	if !c.IsLogin {
		c.ServeJSONError("api.error.unauthorized", "ERR_UNAUTHORIZED", nil, false)
		return
	}
}

func (c *APIBaseController) ServeJSONMessage(message string) {
	r := NewJSONResponse()
	r.Message = message
	c.Data["json"] = r
	c.ServeJSON()
}

func (c *APIBaseController) ServeJSONData(data interface{}) {
	r := NewJSONResponse()
	r.Data = data
	c.Data["json"] = r
	c.ServeJSON()
}

func (c *APIBaseController) ServeJSONError(messageKey, code string, err error, exposeDetail bool) {
	detail := ""
	if exposeDetail && err != nil {
		detail = sanitizeTechnicalDetail(err.Error())
	}
	c.Data["json"] = JSONResponse{
		Status:  "error",
		Message: c.T(messageKey),
		Code:    code,
		Detail:  detail,
	}
	if err != nil && exposeDetail {
		logs.Warning("%s: %s", code, sanitizeTechnicalDetail(err.Error()))
	} else {
		logs.Warning("%s", code)
	}
	c.Ctx.Output.SetStatus(400)
	c.ServeJSON()
}
