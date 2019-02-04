#!/bin/bash

IPV4_ADDRESS=${IPV4_ADDRESS:-"192.168.129.1/24"}
IPV6_ADDRESS=${IPV6_ADDRESS:-"fdff:eedd:ccbb::1/64"}
ALLOWED_IPS=${ALLOWED_IPS:-"192.168.129.254/32, fdff:eedd:ccbb::ffff/128"}

INTERFACE=${INTERFACE:-"wg0rnd"}
MIN_PORT=${MIN_PORT:-49152}
MAX_PORT=${MAX_PORT:-65535}
CONFIG_FILE_DIR=$(mktemp -d)
chmod 0700 ${CONFIG_FILE_DIR}

CONFIG_FILE_PATH="${CONFIG_FILE_DIR}/${INTERFACE}.conf"

__cleanup() {
    wg-quick down "${CONFIG_FILE_PATH}"
    [[ -d "${CONFIG_FILE_DIR}" ]] && rm -r "${CONFIG_FILE_DIR}"
}

trap 'trap __cleanup EXIT' HUP INT QUIT KILL TERM
trap __cleanup EXIT

while read -r line || [[ -n ${line} ]];
do
    read -r method remote_pubkey <<<${line}
    if [[ "${method}" != "INIT" ]];
    then
        echo ERROR
        continue
    fi
    private_key=$(wg genkey)

    port=$((MIN_PORT + $RANDOM % (MAX_PORT - MIN_PORT)))
    conf=$(cat <<EOF
[Interface]
PrivateKey = ${private_key}
Address = ${IPV4_ADDRESS}
Address = ${IPV6_ADDRESS}
ListenPort = ${port}

[Peer]
PublicKey = ${remote_pubkey}
AllowedIPs = ${ALLOWED_IPS}
EOF
    );

    wg-quick down "${CONFIG_FILE_PATH}"
    echo "$conf" > "${CONFIG_FILE_PATH}"
    wg-quick up "$CONFIG_FILE_PATH"

    echo "OK" $(wg pubkey <<<${private_key}) $port
done <${1:-/dev/stdin}
