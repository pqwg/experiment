#!/bin/sh -e

rm -f wireguard.ko
make debug -j2 -B

sudo dmesg -c > /dev/null
sudo rmmod wireguard.ko || true
sudo insmod wireguard.ko
sudo ip link add dev wg0 type wireguard
sudo dmesg
