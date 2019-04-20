#!/bin/sh -e

./install.sh

mkdir -p /etc/wireguard

private_key=`wg genkey`
public_key=`printf ${private_key} | wg pubkey`
echo "Public Key: ${public_key}"

printf 'Please enter wireguard configuration name: [wg0] '
read wg_cfg_name
: ${wg_cfg_name:='wg0'}

printf 'Please enter address: [192.168.128.2/24] '
read address
: ${address:='192.168.128.2/24'}

printf 'Please enter peer public key: '
read peer_public_key

printf 'Please enter peer persistent keep-alive (seconds): '
read keep_alive

printf 'Please enter endpoint: '
read endpoint

printf 'Please enter peer allowed ips: [192.168.128.0/24] '
read peer_allowed_ips
: ${peer_allowed_ips:='192.168.128.0/24'}

cat > /etc/wireguard/${wg_cfg_name}.conf <<EOF
[Interface]
Address = ${address}
PrivateKey = ${private_key}
ListenPort = 8443

[Peer]
PublicKey = ${peer_public_key}\
`printf "${keep_alive:+\nPersistentKeepalive = ${keep_alive}}"`
Endpoint = ${endpoint}
AllowedIPs = ${peer_allowed_ips}
EOF
