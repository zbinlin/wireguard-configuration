sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o $I -j MASQUERADE
iptables -t filter -A FORWARD -i wg+ -j ACCEPT
iptables -t filter -A FORWARD -o wg+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

sysctl -w net.ipv6.conf.all.accept_ra=2 net.ipv6.conf.default.accept_ra=2 net.ipv6.conf.all.forwarding=1 net.ipv6.conf.default.forwarding=1
ip6tables -t nat -A POSTROUTING -o $I -j MASQUERADE
ip6tables -t filter -A FORWARD -i wg+ -j ACCEPT
ip6tables -t filter -A FORWARD -o wg+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT


firewall-cmd --zone=public --add-port=853/upd --permanent
firewall-cmd --zone=public --add-port=8443/tcp --permanent

firewall-cmd --direct --permanent --add-rule ipv4 nat POSTROUTING 0 -o eth0 -j MASQUERADE
firewall-cmd --direct --permanent --add-rule ipv4 filter FORWARD 0 -i wg+ -j ACCEPT
firewall-cmd --direct --permanent --add-rule ipv4 filter FORWARD 0 -o wg+ -m state --state RELATED,ESTABLISHED -j ACCEPT

firewall-cmd --direct --permanent --add-rule ipv4 filter FORWARD 0 -i tun+ -j ACCEPT
firewall-cmd --direct --permanent --add-rule ipv4 filter FORWARD 0 -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -t filter -A INPUT -p udp --dport 49152:65535 -j ACCEPT


# nftables
nft add table inet wg-random-port
nft add chain inet wg-random-port forward \{ type filter hook forward priority filter - 1 \;\}
nft add rule inet wg-random-port forward meta iifname "wg*" accept
nft add rule inet wg-random-port forward ct state \{ established, related \} meta oifname "wg*" accept
nft add chain inet wg-random-port postrouting \{ type nat hook postrouting priority srcnat \;\}
nft add rule inet wg-random-port postrouting meta iifname "wg*" meta oifname != "wg*" masquerade
