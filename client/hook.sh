#!/bin/bash

set -e

case $1 in
    (up)
        cd "$( dirname "${BASH_SOURCE[0]}" )"
        nft -f ./domestic.nft || true
        ip -4 route add 0.0.0.0/0 dev $WG_DEV table $FWMARK
        ip -6 route add ::/0 dev $WG_DEV table $FWMARK
        ip -4 rule add fwmark $FWMARK table $FWMARK
        ip -6 rule add fwmark $FWMARK table $FWMARK
        ip -4 rule add table main suppress_prefixlength 0
        ip -6 rule add table main suppress_prefixlength 0
        ip -4 rule add to $ENDPOINT table main || ip -6 rule add to $ENDPOINT table main
        ;;
    (down)
        ip -4 rule delete to $ENDPOINT table main || ip -6 rule delete to $ENDPOINT table main
        ip -6 rule delete table main suppress_prefixlength 0
        ip -4 rule delete table main suppress_prefixlength 0
        ip -6 rule delete fwmark $FWMARK table $FWMARK
        ip -4 rule delete fwmark $FWMARK table $FWMARK
        nft delete table inet wg.domestic || true
        ;;
    (*)
        echo "Usage: ./hook.sh [up|down]"
        exit 1
        ;;
esac
