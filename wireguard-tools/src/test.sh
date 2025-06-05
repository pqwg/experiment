#!/bin/sh -e

echo "Before"
sudo ./wg show

echo "Setting up"
sudo ./wg addconf wg0 wg.conf

echo "Afterwards"
sudo ./wg show
