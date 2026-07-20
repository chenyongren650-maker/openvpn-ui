#!/bin/sh
set -eu

BASE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RUNTIME_DIR="${BASE_DIR}/.runtime"
FIXTURE_DIR="${BASE_DIR}/fixtures"

if [ -L "${RUNTIME_DIR}" ]; then
  echo "Refusing to use symlinked runtime directory: ${RUNTIME_DIR}" >&2
  exit 1
fi

case "${RUNTIME_DIR}" in
  /opt/openvpn|/opt/openvpn/*)
    echo "Refusing to use production OpenVPN directory: ${RUNTIME_DIR}" >&2
    exit 1
    ;;
esac

umask 077
mkdir -p \
  "${RUNTIME_DIR}/clients" \
  "${RUNTIME_DIR}/config" \
  "${RUNTIME_DIR}/db" \
  "${RUNTIME_DIR}/log" \
  "${RUNTIME_DIR}/pki" \
  "${RUNTIME_DIR}/staticclients"

copy_if_missing() {
  source_file=$1
  target_file=$2

  if [ ! -e "${target_file}" ]; then
    cp -p "${source_file}" "${target_file}"
  fi
}

copy_if_missing "${FIXTURE_DIR}/server.conf" "${RUNTIME_DIR}/server.conf"
copy_if_missing "${FIXTURE_DIR}/config/client.conf" "${RUNTIME_DIR}/config/client.conf"
copy_if_missing "${FIXTURE_DIR}/config/easy-rsa.vars" "${RUNTIME_DIR}/config/easy-rsa.vars"
copy_if_missing "${FIXTURE_DIR}/fw-rules.sh" "${RUNTIME_DIR}/fw-rules.sh"
copy_if_missing "${FIXTURE_DIR}/checkpsw.sh" "${RUNTIME_DIR}/checkpsw.sh"

chmod 700 "${RUNTIME_DIR}" "${RUNTIME_DIR}"/*
chmod 600 \
  "${RUNTIME_DIR}/server.conf" \
  "${RUNTIME_DIR}/config/client.conf" \
  "${RUNTIME_DIR}/config/easy-rsa.vars"
chmod 700 "${RUNTIME_DIR}/fw-rules.sh" "${RUNTIME_DIR}/checkpsw.sh"

echo "Development runtime prepared at ${RUNTIME_DIR}"
