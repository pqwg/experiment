#!/bin/bash

echo "This script is based on AWS Linux 2023, which seems Fedora-based."

sudo dnf install -y \
	python3 zsh bash kernel-devel kernel-modules-extra \
	kernel6.12 kernel6.12-modules-extra kernel-tools tmux \
	kernel-headers iproute-tc iptables python-unversioned-command

echo "net.core.message_cost = 0
kernel.printk_ratelimit = 0
kernel.printk_ratelimit_burst = 9999990" | sudo tee /etc/sysctl.d/10-experiment.conf

echo "blacklist wireguard
libchacha20poly1305
udp_tunnel
ip6_udp_tunnel
curve25519-x86_64" | sudo tee /etc/modules-load.d/wireguard.conf

version=$(rpm -q --qf '%{version}-%{release}.%{arch}\n' kernel6.12 | sort -V | tail -1)
sudo grubby --set-default "/boot/vmlinuz-$version"

echo "Now reboot please"
