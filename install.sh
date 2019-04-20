#!/bin/sh -e

if ! command -v wg >/dev/null 2>&1;
then
	echo 'Wireguard not found!';
	dist=$(LANG=C hostnamectl status | grep 'Operating System:' | awk '{print $3}')
	case "${dist}" in
		'Debian' )
			echo 'Installing...'
			printf 'deb http://deb.debian.org/debian/ unstable main\n' > /etc/apt/sources.list.d/unstable.list
			printf 'Package: *\nPin: release a=unstable\nPin-Priority: 150\n' > /etc/apt/preferences.d/limit-unstable
			apt update
			apt install -yq wireguard
			;;
		'Arch' )
			echo 'Installing...'
			pacman -Sy --confirm wireguard-arch wireguard-tools
			;;
		* )
			echo 'Please install wireguard from https://www.wireguard.com manually.'
			;;
	esac
fi
