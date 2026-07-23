package lib

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/d3vilh/openvpn-ui/state"
)

const (
	certificateScriptsDir = "/opt/scripts"
	genClientScript       = "/opt/scripts/genclient.sh"
	restartScript         = "/opt/scripts/restart.sh"
)

var safeCertificateNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)

var ErrInvalidCertificateInput = errors.New("certificate input is invalid")

type CertificateCreationRequest struct {
	Name       string
	StaticIP   string
	Passphrase string
	ExpireDays string
	Email      string
	Country    string
	Province   string
	City       string
	Org        string
	OrgUnit    string
	TFAName    string
	TFAIssuer  string
}

type certificateScriptCommand struct {
	binary      string
	args        []string
	workingDir  string
	environment []string
}

// Cert
// https://groups.google.com/d/msg/mailing.openssl.users/gMRbePiuwV0/wTASgPhuPzkJ
type Cert struct {
	EntryType   string
	Expiration  string
	ExpirationT time.Time
	IsExpiring  bool
	Revocation  string
	RevocationT time.Time
	Serial      string
	FileName    string
	Details     *Details
}

type Details struct {
	Name             string
	CN               string
	Country          string
	State            string
	City             string
	Organisation     string
	OrganisationUnit string
	Email            string
	LocalIP          string
	TFAName          string
}

func ReadCerts(path string) ([]*Cert, error) {
	certs := make([]*Cert, 0)
	text, err := os.ReadFile(path)
	if err != nil {
		return certs, err
	}
	lines := strings.Split(trim(string(text)), "\n")
	for _, line := range lines {
		fields := strings.Split(trim(line), "\t")
		if len(fields) != 6 {
			return certs,
				fmt.Errorf("incorrect number of lines in line: \n%s\n. Expected %d, found %d",
					line, 6, len(fields))
		}
		expT, _ := time.Parse("060102150405Z", fields[1])
		expTA := time.Now().AddDate(0, 0, 30).After(expT) // If cer will expire in 30 days, raise this flag
		//logs.Debug("ExpirationT: %v, IsExpiring: %v", expT, expTA) // logging
		revT, _ := time.Parse("060102150405Z", fields[2])
		c := &Cert{
			EntryType:   fields[0],
			Expiration:  fields[1],
			ExpirationT: expT,
			IsExpiring:  expTA,
			Revocation:  fields[2],
			RevocationT: revT,
			Serial:      fields[3],
			FileName:    fields[4],
			Details:     parseDetails(fields[5]),
		}
		certs = append(certs, c)
	}

	return certs, nil
}

func parseDetails(d string) *Details {
	details := &Details{}
	lines := strings.Split(trim(d), "/")
	for _, line := range lines {
		if strings.Contains(line, "") {
			fields := strings.Split(trim(line), "=")
			switch fields[0] {
			case "name":
				details.Name = fields[1]
			case "CN":
				details.CN = fields[1]
			case "C":
				details.Country = fields[1]
			case "ST":
				details.State = fields[1]
			case "L":
				details.City = fields[1]
			case "O":
				details.Organisation = fields[1]
			case "OU":
				details.OrganisationUnit = fields[1]
			case "emailAddress":
				details.Email = fields[1]
			case "LocalIP":
				details.LocalIP = fields[1]
			case "2FAName":
				details.TFAName = fields[1]
			default:
				if line != "" && !strings.Contains(line, "name") && !strings.Contains(line, "LocalIP") {
					logs.Warn(fmt.Sprintf("Undefined entry: %s", line))
				}
			}
		}
	}
	return details
}

func trim(s string) string {
	return strings.Trim(strings.Trim(s, "\r\n"), "\n")
}

func CreateCertificate(request CertificateCreationRequest) error {
	command, err := buildCreateCertificateCommand(request)
	if err != nil {
		return err
	}

	logs.Info(
		"Lib: Creating certificate: name=%s, staticip=%s, expiredays=%s",
		request.Name,
		request.StaticIP,
		request.ExpireDays,
	)
	path := filepath.Join(state.GlobalCfg.OVConfigPath, "pki", "index.txt")
	existsError := errors.New("a certificate already exists for this name")
	certs, err := ReadCerts(path)
	if err != nil {
		return errors.New("read certificate index")
	}
	for _, v := range certs {
		if v.Details.Name == request.Name || v.Details.CN == request.Name {
			return existsError
		}
	}

	if err := runCertificateScript(command); err != nil {
		logs.Error("ERR_CERT_CREATE_COMMAND")
		return err
	}
	if request.StaticIP != "" {
		staticClientPath := filepath.Join(
			state.GlobalCfg.OVConfigPath,
			"staticclients",
			request.Name,
		)
		if err := writeAtomicFile(
			staticClientPath,
			[]byte("ifconfig-push "+request.StaticIP+" 255.255.255.0\n"),
			0o600,
		); err != nil {
			logs.Error("ERR_CERT_STATIC_CONFIG_WRITE")
			return errors.New("write static client configuration")
		}
	}
	return nil
}

func Restart() error {
	if err := runCertificateScript(certificateScriptCommand{
		binary:     restartScript,
		workingDir: certificateScriptsDir,
	}); err != nil {
		logs.Error("ERR_OPENVPN_RESTART_COMMAND")
		return errors.New("restart OpenVPN")
	}
	return nil
}

func buildCreateCertificateCommand(
	request CertificateCreationRequest,
) (certificateScriptCommand, error) {
	if !validPortableCertificateName(request.Name) ||
		!validOptionalIPv4(request.StaticIP) ||
		!validCertificateExpiry(request.ExpireDays) ||
		!validOptionalPortableCertificateName(request.TFAName) ||
		!validCertificateText(request.TFAIssuer, 128) ||
		!validCertificateText(request.Email, 254) ||
		!validCertificateText(request.Country, 128) ||
		!validCertificateText(request.Province, 128) ||
		!validCertificateText(request.City, 128) ||
		!validCertificateText(request.Org, 128) ||
		!validCertificateText(request.OrgUnit, 128) ||
		!validCertificateText(request.Passphrase, 4096) {
		return certificateScriptCommand{}, ErrInvalidCertificateInput
	}

	certificateIP := request.StaticIP
	if certificateIP == "" {
		certificateIP = "dynamic.pool"
	}
	args := []string{request.Name, certificateIP}
	if request.Passphrase != "" {
		args = append(args, request.Passphrase)
	}
	return certificateScriptCommand{
		binary:     genClientScript,
		args:       args,
		workingDir: certificateScriptsDir,
		environment: []string{
			"KEY_NAME=" + request.Name,
			"TFA_NAME=" + request.TFAName,
			"TFA_ISSUER=" + request.TFAIssuer,
			"EASYRSA_CERT_EXPIRE=" + request.ExpireDays,
			"EASYRSA_REQ_EMAIL=" + request.Email,
			"EASYRSA_REQ_COUNTRY=" + request.Country,
			"EASYRSA_REQ_PROVINCE=" + request.Province,
			"EASYRSA_REQ_CITY=" + request.City,
			"EASYRSA_REQ_ORG=" + request.Org,
			"EASYRSA_REQ_OU=" + request.OrgUnit,
		},
	}, nil
}

func ValidateCertificateCreationRequest(request CertificateCreationRequest) error {
	_, err := buildCreateCertificateCommand(request)
	return err
}

func runCertificateScript(command certificateScriptCommand) error {
	if command.binary == "" || command.workingDir != certificateScriptsDir {
		return ErrInvalidCertificateInput
	}
	process := exec.Command(command.binary, command.args...)
	process.Dir = command.workingDir
	process.Env = append(os.Environ(), command.environment...)
	if err := process.Run(); err != nil {
		return errors.New("certificate command failed")
	}
	return nil
}

func validPortableCertificateName(value string) bool {
	return value != "." && value != ".." && safeCertificateNamePattern.MatchString(value)
}

func validOptionalPortableCertificateName(value string) bool {
	return value == "" || validPortableCertificateName(value)
}

func validOptionalIPv4(value string) bool {
	if value == "" {
		return true
	}
	parsed := net.ParseIP(value)
	return parsed != nil && parsed.To4() != nil && parsed.To4().String() == value
}

func validCertificateExpiry(value string) bool {
	days, err := strconv.Atoi(value)
	return err == nil && days >= 1 && days <= 36500
}

func validCertificateText(value string, maxLength int) bool {
	if len(value) > maxLength || strings.IndexByte(value, 0) >= 0 {
		return false
	}
	return !strings.ContainsAny(value, "\r\n")
}

func writeAtomicFile(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporaryFile, err := os.CreateTemp(directory, ".certificate-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporaryFile.Name()
	defer os.Remove(temporaryPath)

	if err := temporaryFile.Chmod(mode); err != nil {
		temporaryFile.Close()
		return err
	}
	if _, err := temporaryFile.Write(data); err != nil {
		temporaryFile.Close()
		return err
	}
	if err := temporaryFile.Sync(); err != nil {
		temporaryFile.Close()
		return err
	}
	if err := temporaryFile.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
