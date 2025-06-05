#!/bin/bash -ex

sudo ./reset.sh
sudo rmmod wireguard || true
./setup_configs.py
sudo dmesg -c > /dev/null
sudo insmod wireguard.ko
for file in client*.conf; do
    index=$(echo "$file" | sed -n 's/client\([[:digit:]]\+\).conf/\1/p')
    sudo ./setup_ns.sh $index ${EXPERIMENTS:-1} &
    sleep 1
done

wait

echo "Waiting for all handshakes to settle"
sleep 100
sudo dmesg > /dev/null
sudo dmesg > dmesg.log
