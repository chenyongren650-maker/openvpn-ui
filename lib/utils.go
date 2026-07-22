package lib

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/core/validation"
	"github.com/d3vilh/openvpn-ui/i18n"
)

// CreateValidationMap ranslates validation structure to map
// that can be easly presented in template
func CreateValidationMap(valid validation.Validation, localizer *i18n.Localizer) map[string]map[string]string {
	v := make(map[string]map[string]string)
	/*
			{
				"email": {
					"Requrired" : "Can not be empty"
				},
				"password" :{

			  }
		  }
	*/
	for _, err := range valid.Errors {
		logs.Notice(err.Key, err.Message)
		k := strings.Split(err.Key, ".")
		var field, errorType string
		if len(k) > 1 {
			field = k[0]
			errorType = k[1]
		} else {
			field = err.Key
			errorType = " "
		}
		logs.Error(field)
		if _, ok := v[field]; !ok {
			v[field] = make(map[string]string)
		}
		message := localizer.T("validation.invalid")
		switch err.Name {
		case "Required":
			message = localizer.T("validation.required")
		case "Email":
			message = localizer.T("validation.email")
		case "MinSize":
			message = localizer.T("validation.min_size", err.LimitValue)
		case "MaxSize":
			message = localizer.T("validation.max_size", err.LimitValue)
		default:
			if err.Message == "Passwords do not match" {
				message = localizer.T("validation.password_mismatch")
			}
		}
		v[field][errorType] = message
	}
	return v

}

// Dump any structure as json string
func Dump(obj interface{}) {
	result, _ := json.MarshalIndent(obj, "", "\t")
	logs.Debug(string(result))
}

// ConfSaveToFile saves the given text to the specified file path, replacing Windows-style line endings with Unix-style line endings.
func ConfSaveToFile(destPath string, text string) error {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	err := os.WriteFile(destPath, []byte(text), 0644)
	if err != nil {
		return fmt.Errorf("error writing file: %w", err)
	}
	return nil
}
