#!/bin/sh

prestart() {
    iptables -t filter -A INPUT -i wg+ -j ACCEPT
    iptables -t filter -A OUTPUT -o wg+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ip6tables -t filter -A INPUT -i wg+ -j ACCEPT
    ip6tables -t filter -A OUTPUT -o wg+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
}

postend() {
    iptables -t filter -D INPUT -i wg+ -j ACCEPT
    iptables -t filter -D OUTPUT -o wg+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ip6tables -t filter -D INPUT -i wg+ -j ACCEPT
    ip6tables -t filter -D OUTPUT -o wg+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
}

prestart
trap 'trap postend EXIT' HUP INT QUIT KILL TERM
trap postend EXIT
socat EXEC:./server.sh,pty,rawer TCP-LISTEN:12345,bind=192.168.128.1,fork,reuseaddr
