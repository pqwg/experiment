#!/bin/bash

sudo ip netns delete srv_ns
sudo ip netns delete cli_ns

sudo rmmod wireguard
sudo dmesg -c >/dev/null

if ! [ "$1" = "" ]; then
	experiment="$1"
else
	experiment=pq-x25519mock
fi

if ! [ -e "$HOME/wgtest/wgtest-${experiment}/vars" ]; then
	echo "Invalid argument, ${experiment} is not valid"
	exit 1
fi

source $HOME/wgtest/wgtest-${experiment}/vars

set -e

pushd ./wireguard-linux-compat/src
rm -f kem rkem
ln -s kems/$KEM kem
ln -s rkems/${RKEM} rkem
make -B -j3 debug
sudo insmod ./wireguard.ko
popd

pushd ./wireguard-tools/src
rm -f kem rkem
ln -s kems/$KEM kem
ln -s rkems/${RKEM} rkem
make -B -j3 wg
popd

set +e

cd $HOME/wgtest/wgtest-${experiment}
sudo ./setup_ns.sh
