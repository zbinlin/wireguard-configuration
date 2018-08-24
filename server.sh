sysctl net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o $I -j MASQUERADE
iptables -t filter -A FORWARD -i $wg -j ACCEPT
iptables -t filter -A FORWARD -o $wg -m state --state RELATED,ESTABLISHED -j ACCEPT


firewall-cmd --direct --permanent --add-rule ipv4 nat POSTROUTING 0 -o eth0 -j MASQUERADE
firewall-cmd --direct --permanent --add-rule ipv4 filter FORWARD 0 -i wg+ -j ACCEPT
firewall-cmd --direct --permanent --add-rule ipv4 filter FORWARD 0 -o wg+ -m state --state RELATED,ESTABLISHED -j ACCEPT
