#!/bin/bash
#updates Pi running Raspberry Pi OS, Pi-Hole, and Pi-VPN

sudo apt update
sudo apt upgrade -y

sudo pihole -g
sudo pihole up

if [ ! -d "$HOME/dev/linux-scripts/logs" ]; then
  mkdir $HOME/dev/linux-scripts/logs
fi

timestamp=$(date "+%Y-%m-%d_%H:%M:%S")

touch $HOME/dev/linux-scripts/logs/pi-hole-update-$timestamp.txt
echo "Pi updated on $timestamp" > $HOME/dev/linux-scripts/logs/pi-hole-update-$timestamp.txt
