#!/bin/sh

set -e

ADDRESS=192.168.128.1
PORT=12345
export INTERFACE="wg0rand"

NFTABLES_TABLE_NAME="wg-random-${PORT}"

prestart() {
    if command -v nft >/dev/null;
    then
        cat <<-EOF | nft -f -
table inet ${NFTABLES_TABLE_NAME} {
    chain forward {
        type filter hook forward priority filter - 1;
        meta iifname ${INTERFACE} accept
        ct state { established, related } meta oifname ${INTERFACE} accept
    }
    chain postrouting {
        type nat hook postrouting priority srcnat;
        meta iifname ${INTERFACE} meta oifname != ${INTERFACE} masquerade
    }
}
EOF
    else
        iptables -t filter -A FORWARD -i ${INTERFACE} -j ACCEPT
        iptables -t filter -A FORWARD -o ${INTERFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        iptables -t nat -A POSTROUTING -i ${INTERFACE} -o !${INTERFACE} -j MASQUERADE
        ip6tables -t filter -A FORWARD -i ${INTERFACE} -j ACCEPT
        ip6tables -t filter -A FORWARD -o ${INTERFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        ip6tables -t nat -A POSTROUTING -i ${INTERFACE} -o !${INTERFACE} -j MASQUERADE
    fi
}

postend() {
    if command -v nft >/dev/null;
    then
        cat <<-EOF | nft -f -
delete table inet ${NFTABLES_TABLE_NAME}
EOF
    else
        iptables -t filter -D FORWARD -i ${INTERFACE} -j ACCEPT
        iptables -t filter -D FORWARD -o ${INTERFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        iptables -t nat -D POSTROUTING -i ${INTERFACE} -o !${INTERFACE} -j MASQUERADE
        ip6tables -t filter -D FORWARD -i ${INTERFACE} -j ACCEPT
        ip6tables -t filter -D FORWARD -o ${INTERFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        ip6tables -t nat -D POSTROUTING -i ${INTERFACE} -o !${INTERFACE} -j MASQUERADE
    fi
}

prestart
trap 'trap postend EXIT' HUP INT QUIT KILL TERM
trap postend EXIT
socat EXEC:./server.sh,pty,rawer TCP-LISTEN:${PORT},bind=${ADDRESS},fork,reuseaddr
