#!/bin/bash

set -e

: ${FWMARK:=0x00003000}

usage() {
	echo "Usage: $0 [option] <up|down>"
	echo "options:"
	echo "    -i INTERFACE    interface"
	echo "    -h              Help"
}

while getopts ":i:" option;
do
	case $option in
		i)
			INTERFACE=$OPTARG
			;;
		\?)
			usage
			exit 1
			;;
	esac
done
shift `expr $OPTIND - 1`

if [[ $1 == "" ]]
then
    echo "Missing argument <up|down>"
    usage
    exit 1
fi

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
        cd "$( dirname "${BASH_SOURCE[0]}" )"
        nft -f ./domestic.nft
        ip -4 route add 0.0.0.0/0 dev $WG_DEV table $FWMARK
        ip -6 route add ::/0 dev $WG_DEV table $FWMARK
        ip -4 rule add fwmark $FWMARK table $FWMARK
        ip -6 rule add fwmark $FWMARK table $FWMARK
        ip -4 rule add table main suppress_prefixlength 0
        ip -6 rule add table main suppress_prefixlength 0
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
        ip -6 rule delete table main suppress_prefixlength 0 || true
        ip -4 rule delete table main suppress_prefixlength 0 || true
        ip -6 rule delete fwmark $FWMARK table $FWMARK || true
        ip -4 rule delete fwmark $FWMARK table $FWMARK || true
        nft delete table inet wg.domestic || true
        ;;
    (*)
        usage
        exit 1
        ;;
esac
