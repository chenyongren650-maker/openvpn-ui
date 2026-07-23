package main

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
	"github.com/d3vilh/openvpn-ui/i18n"
	"github.com/d3vilh/openvpn-ui/lib"
	"github.com/d3vilh/openvpn-ui/models"
	"github.com/d3vilh/openvpn-ui/routers"
	"github.com/d3vilh/openvpn-ui/services"
	"github.com/d3vilh/openvpn-ui/state"
)

func main() {
	configDir := flag.String("config", "conf", "Path to config dir")
	flag.Parse()

	configFile := filepath.Join(*configDir, "app.conf")
	fmt.Println("Config file:", configFile)

	if err := web.LoadAppConfig("ini", configFile); err != nil {
		panic(err)
	}
	localesDir := filepath.Clean(filepath.Join(*configDir, "..", "locales"))
	if err := i18n.Load(localesDir); err != nil {
		panic(fmt.Errorf("load language resources: %w", err))
	}

	if err := models.InitDB(); err != nil {
		panic(fmt.Errorf("initialize database: %w", err))
	}
	models.CreateDefaultUsers()
	defaultSettings, err := models.CreateDefaultSettings()
	if err != nil {
		panic(err)
	}

	models.CreateDefaultOVConfig(*configDir, defaultSettings.OVConfigPath, defaultSettings.MIAddress, defaultSettings.MINetwork)
	models.CreateDefaultOVClientConfig(*configDir, defaultSettings.OVConfigPath, defaultSettings.MIAddress, defaultSettings.MINetwork)
	models.CreateDefaultEasyRSAConfig(*configDir, defaultSettings.EasyRSAPath, defaultSettings.MIAddress, defaultSettings.MINetwork)
	state.GlobalCfg = *defaultSettings

	db, err := orm.GetDB("default")
	if err != nil {
		panic(fmt.Errorf("get certificate metadata database: %w", err))
	}
	certificateIndexPath := filepath.Join(state.GlobalCfg.OVConfigPath, "pki", "index.txt")
	importResult, err := services.ImportCertificateMetadataFile(
		context.Background(),
		db,
		certificateIndexPath,
	)
	if err != nil {
		panic(fmt.Errorf("import certificate metadata: %w", err))
	}
	if importResult.SourceMissing {
		logs.Warn("Certificate metadata import skipped because the configured PKI index is not ready")
	} else {
		logs.Info(
			"Certificate metadata import completed: inserted=%d updated=%d unchanged=%d",
			importResult.Inserted,
			importResult.Updated,
			importResult.Unchanged,
		)
	}

	routers.Init(*configDir)

	lib.AddFuncMaps()
	web.Run()
}
