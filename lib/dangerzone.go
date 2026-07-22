package lib

import (
	"fmt"
	"os/exec"

	"github.com/beego/beego/v2/core/logs"
	"github.com/d3vilh/openvpn-ui/state"
)

func DeletePKI(name string) error {
	//logs.Info("Lib: Deleting:", name)
	cmd := exec.Command("/bin/bash", "-c",
		fmt.Sprintf(
			"cd /opt/scripts/ && "+
				"./remove.sh %s", name))
	cmd.Dir = state.GlobalCfg.OVConfigPath
	_, err := cmd.CombinedOutput()
	if err != nil {
		logs.Error("ERR_MAINTENANCE_DELETE_COMMAND")
		return err
	}
	return nil
}

func InitPKI(name string) error {
	//logs.Info("Lib: Runing init for:", name)
	cmd := exec.Command("/bin/bash", "-c",
		fmt.Sprintf(
			"cd /opt/scripts/ && "+
				"./generate_ca_and_server_certs.sh %s", name))
	cmd.Dir = state.GlobalCfg.OVConfigPath
	_, err := cmd.CombinedOutput()
	if err != nil {
		logs.Error("ERR_MAINTENANCE_INIT_COMMAND")
		return err
	}
	return nil
}

func RestartContainer(name string) error {
	//logs.Info("Lib: Restarting:", name)
	cmd := exec.Command("/bin/bash", "-c",
		fmt.Sprintf(
			"cd /opt/scripts/ && "+
				"./restart.sh %s", name))
	cmd.Dir = state.GlobalCfg.OVConfigPath
	_, err := cmd.CombinedOutput()
	if err != nil {
		logs.Error("ERR_CONTAINER_RESTART_COMMAND")
		return err
	}
	return nil
}
