package lib

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenClientUsesExactLockedAtomicTOTPWrite(t *testing.T) {
	scriptPath := filepath.Join("..", "build", "assets", "genclient.sh")
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read genclient.sh: %v", err)
	}
	script := string(data)
	required := []string{
		"flock -x 9",
		`$1 == target { count++ }`,
		`mktemp "$OPENVPN_DIR/clients/.oath.secrets.`,
		`mv -- "$OATH_TEMP" "$OATH_SECRETS"`,
		`chmod 600 "$OATH_SECRETS"`,
		`chmod 600 "$OPENVPN_DIR/clients/$CERT_NAME.png"`,
		"cleanup_totp_files",
	}
	for _, fragment := range required {
		if !strings.Contains(script, fragment) {
			t.Fatalf("genclient.sh is missing required TOTP hardening fragment %q", fragment)
		}
	}
	for _, forbidden := range []string{
		`>> "$OATH_SECRETS"`,
		`grep "$TFA_NAME"`,
		`echo "$USERHASH"`,
		`echo "$BASE32"`,
		`echo "$QRSTRING"`,
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("genclient.sh contains unsafe TOTP fragment %q", forbidden)
		}
	}
}
