#!/bin/bash

ENDPOINT=${ENDPOINT:-"example.org"}
REMOTE_HOSTNAME=${REMOTE_HOSTNAME:-"192.168.128.1"}
REMOTE_PORT=${REMOTE_PORT:-12345}
IPV4_ADDRESS=${IPV4_ADDRESS:-"192.168.129.254/24"}
IPV6_ADDRESS=${IPV6_ADDRESS:-"fdff:eedd:ccbb::ffff/64"}

INTERFACE=wg1rnd
CONFIG_FILE_DIR=$(mktemp -d)
chmod 0700 ${CONFIG_FILE_DIR}

CONFIG_FILE_PATH="${CONFIG_FILE_DIR}/${INTERFACE}.conf"

__cleanup() {
    wg-quick down "${CONFIG_FILE_PATH}"
    [[ -d "${CONFIG_FILE_DIR}" ]] && rm -r "${CONFIG_FILE_DIR}"
}

trap __cleanup EXIT

update() {
    private_key=$(wg genkey)
    ret=$(echo "INIT" "$(wg pubkey <<<${private_key})" | ncat ${REMOTE_HOSTNAME} ${REMOTE_PORT})

    read -r method remote_pubkey port <<<"${ret}"

    echo "Response: ${method} ${remote_pubkey} ${port}" >&2

    if [[ "${method}" != "OK" ]];
    then
        return 1;
    fi

    DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
    conf=$(cat <<EOF
[Interface]
PrivateKey = ${private_key}
Address = ${IPV4_ADDRESS}
Address = ${IPV6_ADDRESS}
PostUp = export PRIORITY=1024; source ${DIR}/post-up.sh
PreDown = export PRIORITY=1024; source ${DIR}/pre-down.sh

[Peer]
PublicKey = ${remote_pubkey}
Endpoint = ${ENDPOINT}:${port}
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0
EOF
    );

    echo "${conf}" > "${CONFIG_FILE_PATH}"
}

wg-quick down wg1 2>/dev/null
while true;
do
    echo Updating...
    wg-quick down "${CONFIG_FILE_PATH}" 2>/dev/null
    wg-quick up wg1
    up=$?
    [[ $up -ne 0 ]] && {
        echo "Error: Could not up wg1!" >&2
        exit 1
    }
    update
    success=$?
    wg-quick down wg1 2>/dev/null
    if [[ $success -eq 0 ]];
    then
        wg-quick up "${CONFIG_FILE_PATH}"
        echo Updated!
        sleep $((300 + $RANDOM % 600)) # 5~15 minutes
    else
        echo "Could not up ${CONFIG_FILE_PATH}!"
        echo "Try agent..."
        sleep 10
    fi
done
