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

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

__cleanup() {
    ret=$?
    wg-quick down ${INTERFACE} 2>/dev/null
    wg-quick down "${CONFIG_FILE_PATH}"
    [[ -d "${CONFIG_FILE_DIR}" ]] && rm -r "${CONFIG_FILE_DIR}"
    exit $ret
}

trap '__=$? && trap __cleanup EXIT && exit $__' HUP INT QUIT KILL TERM
trap __cleanup EXIT

exists() {
    command -v "$1" >/dev/null
    return $?
}

if exists nft
then
    hooks=$(cat <<EOF
PostUp = export ENDPOINT=${ENDPOINT}; export FWMARK=0x00003000; export WG_DEV=${RND_INTERFACE}; source ${DIR}/hook.sh up
PreDown = export ENDPOINT=${ENDPOINT}; export FWMARK=0x00003000; export WG_DEV=${RND_INTERFACE}; source ${DIR}/hook.sh down
Table = off
EOF
    )
else
    hooks=$(cat <<EOF
PostUp = export PRIORITY=1024; source ${DIR}/post-up.sh
PreDown = export PRIORITY=1024; source ${DIR}/pre-down.sh
EOF
    )
fi

update() {
    id=$RANDOM
    private_key=$(wg genkey)
    public_key=$(wg pubkey <<<${private_key})

    echo "Sending public key and Receiving remote public key..." >&2

    coproc CONN {
        if exists socat
        then
            socat - tcp:${REMOTE_HOSTNAME}:${REMOTE_PORT},connect-timeout=10
        elif exists ncat
        then
            ncat -w 10s ${REMOTE_HOSTNAME} ${REMOTE_PORT}
        elif exists nc
        then
            nc -w 10 ${REMOTE_HOSTNAME} ${REMOTE_PORT}
        else
            echo "No found netcat/nmap/socat installed, please install anyone of them!" >&2
            exit 1
        fi
    }
    echo "INIT" "${id}" "${public_key}" >&"${CONN[1]}"
    while read -r line || [[ -n ${line} ]];
    do
        echo $line
        read -r method rid remote_pubkey port <<<${line}

        if [[ "${method}" != "OK" ]];
        then
            echo Invalid response: ${line}! >&2
            continue
        fi

        if [[ "${rid}" != "${id}" ]];
        then
            echo Invalid id: ${rid}! >&2
            continue
        fi

        break;
    done <&"${CONN[0]}"
    [[ -n "$CONN_PID" ]] && kill "$CONN_PID"

    [[ -z "$remote_pubkey" ]] && echo "Could not fetch remote_pubkey!" >&2 && return 1
    [[ -z "$port" ]] && echo "Could not fetch port!" >&2 && return 1

    conf=$(cat <<EOF
[Interface]
PrivateKey = ${private_key}
Address = ${IPV4_ADDRESS}
Address = ${IPV6_ADDRESS}
MTU = ${MTU}
${hooks}

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
        #sleep $((300 + $RANDOM % 600)) # 5~15 minutes
        sleep 100000
    else
        echo "Could not up ${CONFIG_FILE_PATH}!"
        echo "Try again after 10 seconds..."
        sleep 10
    fi
done
