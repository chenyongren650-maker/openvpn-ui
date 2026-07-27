#!/bin/bash
#VERSION 1.4 by d3vilh@github.com aka Mr. Philipp. Updated with Easyrsa 3 support.
# Exit immediately if a command exits with a non-zero status.
set -euo pipefail
umask 077

# .ovpn file path
CERT_NAME=${1:-}
CERT_IP=${2:-}
CERT_PASS=${3:-}
# These VARS shoud be in your ENV before running certgen: TFA_NAME, ISSUER, EASYRSA_CERT_EXPIRE, EASYRSA_REQ_EMAIL, EASYRSA_REQ_COUNTRY, EASYRSA_REQ_PROVINCE, EASYRSA_REQ_CITY, EASYRSA_REQ_ORG, EASYRSA_REQ_OU

EASY_RSA=$(grep -E "^EasyRsaPath\s*=" ../openvpn-ui/conf/app.conf | cut -d= -f2 | tr -d '"' | tr -d '[:space:]')
OPENVPN_DIR=$(grep -E "^OpenVpnPath\s*=" ../openvpn-ui/conf/app.conf | cut -d= -f2 | tr -d '"' | tr -d '[:space:]')
echo "EasyRSA path: $EASY_RSA OVPN path: $OPENVPN_DIR"
OVPN_FILE_PATH="$OPENVPN_DIR/clients/$CERT_NAME.ovpn"
OATH_SECRETS="$OPENVPN_DIR/clients/oath.secrets"   # 2FA secrets file

# Validate username and check for duplicates
if  [[ -z $CERT_NAME ]]; then
    echo 'Name cannot be empty. Exiting...'
    exit 1
elif [[ -f $OVPN_FILE_PATH ]]; then
    echo "User with name $CERT_NAME already exists under openvpn/clients. Exiting..."
    exit 1
fi

export EASYRSA_BATCH=1 # see https://superuser.com/questions/1331293/easy-rsa-v3-execute-build-ca-and-gen-req-silently

echo 'Patching easy-rsa.3.1.1 openssl-easyrsa.cnf...' 
sed -i '/serialNumber_default/d' "$EASY_RSA/openssl-easyrsa.cnf"

echo 'Generate client certificate...'
echo -e "Will use following parameters: \nEASYRSA_CERT_EXPIRE: $EASYRSA_CERT_EXPIRE\nEASYRSA_REQ_EMAIL: $EASYRSA_REQ_EMAIL" #\nEASYRSA_REQ_COUNTRY: $EASYRSA_REQ_COUNTRY\nEASYRSA_REQ_PROVINCE: $EASYRSA_REQ_PROVINCE\nEASYRSA_REQ_CITY: $EASYRSA_REQ_CITY\nEASYRSA_REQ_ORG: $EASYRSA_REQ_ORG\nEASYRSA_REQ_OU: $EASYRSA_REQ_OU"
echo -e "EasyRSA VARS will be used:\n$(cat $EASY_RSA/vars)"

# Copy easy-rsa variables
cd $EASY_RSA

# Generate certificates
if  [[ -z $CERT_PASS ]]; then
    echo 'Without password...'
    ./easyrsa --batch --req-cn="$CERT_NAME" --days="$EASYRSA_CERT_EXPIRE" --req-email="$EASYRSA_REQ_EMAIL" gen-req "$CERT_NAME" nopass 
    #subject="/C=$EASYRSA_REQ_COUNTRY/ST=$EASYRSA_REQ_PROVINCE/L=\"$EASYRSA_REQ_CITY\"/O=\"$EASYRSA_REQ_ORG\"/OU=\"$EASYRSA_REQ_OU\""
else
    echo 'With password...'
    # See https://stackoverflow.com/questions/4294689/how-to-generate-an-openssl-key-using-a-passphrase-from-the-command-line
    # ... and https://stackoverflow.com/questions/22415601/using-easy-rsa-how-to-automate-client-server-creation-process
    # ... and https://github.com/OpenVPN/easy-rsa/blob/master/doc/EasyRSA-Advanced.md
    (echo -e '\n') | ./easyrsa --batch --req-cn="$CERT_NAME" --days="$EASYRSA_CERT_EXPIRE" --req-email="$EASYRSA_REQ_EMAIL" --passin=pass:"${CERT_PASS}" --passout=pass:"${CERT_PASS}" gen-req "$CERT_NAME" 
    #subject="/C=$EASYRSA_REQ_COUNTRY/ST=$EASYRSA_REQ_PROVINCE/L=\"$EASYRSA_REQ_CITY\"/O=\"$EASYRSA_REQ_ORG\"/OU=\"$EASYRSA_REQ_OU\""
fi

# Sign request. Bypass "yes" with export EASYRSA_BATCH=1 
./easyrsa sign-req client "$CERT_NAME"
# Check if 2FA was specified. If not - set to none.
if [ -z "$TFA_NAME" ]; then
    TFA_NAME="none"
fi

# Certificate properties
CA="$(cat $EASY_RSA/pki/ca.crt )"
CERT="$(awk '/-----BEGIN CERTIFICATE-----/{flag=1;next}/-----END CERTIFICATE-----/{flag=0}flag' ./pki/issued/${CERT_NAME}.crt | tr -d '\0')"
KEY="$(cat $EASY_RSA/pki/private/${CERT_NAME}.key)"
TLS_AUTH="$(cat $EASY_RSA/pki/ta.key)"

echo 'Fixing permissions for pki/issued...'
chmod +r $EASY_RSA/pki/issued

echo 'Generating .ovpn file...'
echo "$(cat $OPENVPN_DIR/config/client.conf)
<ca>
$CA
</ca>
<cert>
$CERT
</cert>
<key>
$KEY
</key>
<tls-auth>
$TLS_AUTH
</tls-auth>
" > "$OVPN_FILE_PATH"

echo -e "OpenVPN Client configuration successfully generated!\nCheckout openvpn-server/clients/$CERT_NAME.ovpn"

# Check if $TFA_NAME was specified and not equal to "none". then create 2FA and QR code
if [[ -n ${TFA_NAME:-} ]] && [[ $TFA_NAME != "none" ]]; then
    echo -e "Generating 2FA ...\nName: $TFA_NAME\nIssuer: $TFA_ISSUER"

    if [[ ! $TFA_NAME =~ ^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$ ]] \
        || [[ -z ${TFA_ISSUER:-} ]] \
        || [[ ${#TFA_ISSUER} -gt 128 ]] \
        || [[ $TFA_ISSUER == *$'\n'* ]] \
        || [[ $TFA_ISSUER == *$'\r'* ]]; then
        echo 'Invalid 2FA identity metadata. Exiting...'
        exit 1
    fi

    OATH_LOCK="${OATH_SECRETS}.lock"
    if [[ -L $OATH_LOCK ]]; then
        echo 'Invalid 2FA lock file. Exiting...'
        exit 1
    fi
    touch "$OATH_LOCK"
    chmod 600 "$OATH_LOCK"
    exec 9>>"$OATH_LOCK"
    flock -x 9

    if [[ -L $OATH_SECRETS ]] \
        || { [[ -e $OATH_SECRETS ]] && [[ ! -f $OATH_SECRETS ]]; }; then
        echo 'Invalid 2FA identity file. Exiting...'
        exit 1
    fi
    if [[ -f $OATH_SECRETS ]]; then
        chmod 600 "$OATH_SECRETS"
        MATCH_COUNT=$(awk -F: -v target="$TFA_NAME" \
            '$1 == target { count++ } END { print count + 0 }' \
            "$OATH_SECRETS")
        if [[ $MATCH_COUNT -ne 0 ]]; then
            echo 'The exact 2FA identity already exists. Exiting...'
            exit 1
        fi
    fi

    # Userhash. Random 30 chars
    USERHASH=$(head -c 10 /dev/urandom | openssl sha256 | cut -d ' ' -f2 | cut -b 1-30)

    # Base32 secret from oathtool output
    BASE32=$(oathtool --totp -v "$USERHASH" | grep Base32 | awk '{print $3}')

    # QRCODE STRING
    QRSTRING="otpauth://totp/$TFA_ISSUER:$TFA_NAME?secret=$BASE32&issuer=$TFA_ISSUER"

    QR_TEMP=$(mktemp "$OPENVPN_DIR/clients/.${CERT_NAME}.qr.XXXXXX")
    OATH_TEMP=$(mktemp "$OPENVPN_DIR/clients/.oath.secrets.XXXXXX")
    OATH_BACKUP=$(mktemp "$OPENVPN_DIR/clients/.oath.secrets.backup.XXXXXX")
    OATH_EXISTED=0
    cleanup_totp_files() {
        rm -f -- "$QR_TEMP" "$OATH_TEMP" "$OATH_BACKUP"
        unset USERHASH BASE32 QRSTRING
    }
    trap cleanup_totp_files EXIT
    chmod 600 "$QR_TEMP" "$OATH_TEMP" "$OATH_BACKUP"

    # QR code for user to pass to Google Authenticator or OpenVPN-UI
    /opt/scripts/qrencode "$QRSTRING" > "$QR_TEMP"
    if [[ ! -s $QR_TEMP ]]; then
        echo '2FA QR code generation failed. Exiting...'
        exit 1
    fi

    if [[ -f $OATH_SECRETS ]]; then
        OATH_EXISTED=1
        cp -- "$OATH_SECRETS" "$OATH_TEMP"
        cp -- "$OATH_SECRETS" "$OATH_BACKUP"
    fi
    printf '%s:%s\n' "$TFA_NAME" "$USERHASH" >> "$OATH_TEMP"
    chmod 600 "$OATH_TEMP"
    MATCH_COUNT=$(awk -F: -v target="$TFA_NAME" '
        NF != 2 { invalid = 1 }
        $1 == target { count++ }
        END {
            if (invalid || count != 1) {
                exit 1
            }
        }' "$OATH_TEMP" && printf '1')
    if [[ $MATCH_COUNT != "1" ]]; then
        echo '2FA identity validation failed. Exiting...'
        exit 1
    fi

    mv -- "$OATH_TEMP" "$OATH_SECRETS"
    chmod 600 "$OATH_SECRETS"
    if ! mv -- "$QR_TEMP" "$OPENVPN_DIR/clients/$CERT_NAME.png"; then
        if [[ $OATH_EXISTED -eq 1 ]]; then
            mv -- "$OATH_BACKUP" "$OATH_SECRETS"
            chmod 600 "$OATH_SECRETS"
        else
            rm -f -- "$OATH_SECRETS"
        fi
        echo '2FA QR code replacement failed. Authentication data restored.'
        exit 1
    fi
    chmod 600 "$OPENVPN_DIR/clients/$CERT_NAME.png"
    trap - EXIT
    cleanup_totp_files
    flock -u 9

    else
    echo 'No 2FA specified. exiting'

fi

# A non-sensitive completion marker lets the UI distinguish a completed
# creation from a partially failed script without reading oath.secrets.
COMPLETION_MARKER="$OPENVPN_DIR/clients/.${CERT_NAME}.creation-complete"
TEMP_COMPLETION_MARKER="${COMPLETION_MARKER}.tmp.$$"
umask 077
printf 'name=%s\nstatic_ip=%s\ntfa_name=%s\nissuer=%s\n' \
    "$CERT_NAME" "$CERT_IP" "$TFA_NAME" "$TFA_ISSUER" \
    > "$TEMP_COMPLETION_MARKER"
mv "$TEMP_COMPLETION_MARKER" "$COMPLETION_MARKER"
