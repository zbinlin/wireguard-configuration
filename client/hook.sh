#!/bin/bash

set -e

: ${FWMARK:=0x00003000}

usage() {
    echo "Usage: $0 [option] <up|down>"
    echo "options:"
    echo "    -i INTERFACE    interface"
    echo "    -m METHOD       ebpf/nft"
    echo "    -h              Help"
}

while getopts ":i:m:h" option; do
    case "$option" in
        i)
            INTERFACE="$OPTARG"
            ;;
        m)
            METHOD="$OPTARG"
            ;;
        h)
            usage
            exit 0
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            usage
            exit 1
            ;;
        :)
            echo "Option -$OPTARG requires an argument." >&2
            usage
            exit 1
            ;;
    esac
done

shift $((OPTIND - 1))


if [[ $1 == "" ]]
then
    echo "Missing argument <up|down>"
    usage
    exit 1
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd -P )"

: ${WG_DEV:=$INTERFACE}

if [[ -z "$ENDPOINT" ]];
then
    ENDPOINT=$(wg show ${WG_DEV} endpoints | awk '{gsub(/\[|(\]?:[0-9]+$)/, "", $2); print $2}')
fi

if [[ $ENDPOINT =~ ':' ]]
then
    endpoint_is_ipv6=TRUE
else
    endpoint_is_ipv6=FALSE
fi

case $1 in
    (up)
        if [[ ${METHOD} == "ebpf" ]];
        then
            ${DIR}/ebpf-routing/router-ctl.sh start \
                --cgroup-path /sys/fs/cgroup \
                --pin-dir /sys/fs/bpf/wg_routing \
                --wg-endpoint $ENDPOINT \
                --rule-file ${DIR}/data/var.nft
            nft -f - <<EOF
destroy table inet ebpf.wg.forward;
table inet ebpf.wg.forward {
    chain net.postrouting.srcnat {
        type nat hook postrouting priority srcnat; policy accept;
        fib saddr type != local oifname ${WG_DEV} masquerade;
    }
}
EOF
        else
            nft -f ${DIR}/domestic.nft
        fi
        ip -4 route add 0.0.0.0/0 dev $WG_DEV table $FWMARK
        ip -6 route add ::/0 dev $WG_DEV table $FWMARK
        ip -4 rule add table main suppress_prefixlength 0
        ip -6 rule add table main suppress_prefixlength 0
        ip -4 rule add fwmark $FWMARK table $FWMARK
        ip -6 rule add fwmark $FWMARK table $FWMARK
        if [[ $endpoint_is_ipv6 == TRUE ]]
        then
            ip -6 rule add to $ENDPOINT table main
        else
            ip -4 rule add to $ENDPOINT table main
        fi
        ;;
    (down)
        if [[ $endpoint_is_ipv6 == TRUE ]]
        then
            ip -6 rule delete to $ENDPOINT table main || true
        else
            ip -4 rule delete to $ENDPOINT table main || true
        fi
        ip -6 rule delete fwmark $FWMARK table $FWMARK || true
        ip -4 rule delete fwmark $FWMARK table $FWMARK || true
        ip -6 rule delete table main suppress_prefixlength 0 || true
        ip -4 rule delete table main suppress_prefixlength 0 || true
        if [[ ${METHOD} == "ebpf" ]];
        then
            ${DIR}/ebpf-routing/router-ctl.sh stop --pin-dir /sys/fs/bpf/wg_routing || true
            nft destroy table inet ebpf.wg.forward || true
        else
            nft destroy table inet wg.domestic || nft delete table inet wg.domestic || true
        fi
        ;;
    (*)
        usage
        exit 1
        ;;
esac
