#!/bin/sh -e

function install_for_debian() {
	code_name=$(lsb_release -cs)
	target_release=stable
	case "${code_name}" in
		'buster' )
			echo 'deb http://deb.debian.org/debian buster-backports main' >> /etc/apt/sources.list.d/backports.list
			target_release=buster-backports
			;;
		'stretch' )
			printf 'deb http://deb.debian.org/debian/ unstable main\n' > /etc/apt/sources.list.d/unstable.list
			printf 'Package: *\nPin: release a=unstable\nPin-Priority: 150\n' > /etc/apt/preferences.d/limit-unstable
			target_release=unstable
			;;
		* )
			;;
	esac
	apt update
	apt -t $target_release install -yq wireguard
}

if ! command -v wg >/dev/null 2>&1;
then
	echo 'Wireguard not found!';
	dist=$(LANG=C hostnamectl status | grep 'Operating System:' | awk '{print $3}')
	case "${dist}" in
		'Debian' )
			echo 'Installing...'
			install_for_debian
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
