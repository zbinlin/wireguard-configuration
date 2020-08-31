#!/bin/bash

ENDPOINT=${ENDPOINT:-"example.org"}
REMOTE_HOSTNAME=${REMOTE_HOSTNAME:-"192.168.128.1"}
REMOTE_PORT=${REMOTE_PORT:-12345}
IPV4_ADDRESS=${IPV4_ADDRESS:-"192.168.129.254/24"}
IPV6_ADDRESS=${IPV6_ADDRESS:-"fdff:eedd:ccbb::ffff/64"}
MTU=${MTU:-1420}

INTERFACE=${INTERFACE:-"wg1"}
RND_INTERFACE="${INTERFACE}rnd"
CONFIG_FILE_DIR=$(mktemp -d)
chmod 0700 ${CONFIG_FILE_DIR}

CONFIG_FILE_PATH="${CONFIG_FILE_DIR}/${RND_INTERFACE}.conf"

__cleanup() {
    ret=$?
    wg-quick down ${INTERFACE} 2>/dev/null
    wg-quick down "${CONFIG_FILE_PATH}"
    [[ -d "${CONFIG_FILE_DIR}" ]] && rm -r "${CONFIG_FILE_DIR}"
    exit $ret
}

trap '__=$? && trap __cleanup EXIT && exit $__' HUP INT QUIT KILL TERM
trap __cleanup EXIT


update() {
    private_key=$(wg genkey)

    echo "Sending public key and Receiving remote public key..." >&2

    ret=$(echo "INIT" "$(wg pubkey <<<${private_key})" | ncat -w 10s ${REMOTE_HOSTNAME} ${REMOTE_PORT})
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
MTU = ${MTU}
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

wg-quick down $INTERFACE 2>/dev/null
while true;
do
    echo Updating...
    wg-quick down "${CONFIG_FILE_PATH}" 2>/dev/null
    wg-quick up $INTERFACE
    up=$?
    [[ $up -ne 0 ]] && {
        echo "Error: Could not up $INTERFACE!" >&2
        exit 1
    }
    update
    success=$?
    wg-quick down $INTERFACE 2>/dev/null
    if [[ $success -eq 0 ]];
    then
        wg-quick up "${CONFIG_FILE_PATH}"
        echo Updated!
        sleep $((300 + $RANDOM % 600)) # 5~15 minutes
    else
        echo "Could not up ${CONFIG_FILE_PATH}!"
        echo "Try again after 10 seconds..."
        sleep 10
    fi
done
