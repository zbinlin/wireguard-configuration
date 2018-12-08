sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o $I -j MASQUERADE
iptables -t filter -A FORWARD -i wg+ -j ACCEPT
iptables -t filter -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

sysctl -w net.ipv6.conf.all.accept_ra=2 net.ipv6.conf.default.accept_ra=2 net.ipv6.conf.all.forwarding=1 net.ipv6.conf.default.forwarding=1
ip6tables -t nat -A POSTROUTING -o $I -j MASQUERADE
ip6tables -t filter -A FORWARD -i wg+ -j ACCEPT
ip6tables -t filter -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT


firewall-cmd --zone=public --add-port=853/upd --permanent
firewall-cmd --zone=public --add-port=8443/tcp --permanent

firewall-cmd --direct --permanent --add-rule ipv4 nat POSTROUTING 0 -o eth0 -j MASQUERADE
firewall-cmd --direct --permanent --add-rule ipv4 filter FORWARD 0 -i wg+ -j ACCEPT
firewall-cmd --direct --permanent --add-rule ipv4 filter FORWARD 0 -o wg+ -m state --state RELATED,ESTABLISHED -j ACCEPT

firewall-cmd --direct --permanent --add-rule ipv4 filter FORWARD 0 -i tun+ -j ACCEPT
firewall-cmd --direct --permanent --add-rule ipv4 filter FORWARD 0 -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT
