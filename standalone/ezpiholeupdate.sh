#!/bin/bash
#updates Pi running Raspberry Pi OS, Pi-Hole, and Pi-VPN

sudo apt update
sudo apt upgrade -y

sudo pihole -g
sudo pihole up

path="/home/jvhmx/dev/linux-scripts"
timestamp=$(date "+%Y-%m-%d_%H:%M:%S")

if [ ! -d "$path/dev/linux-scripts/logs" ]; then
  mkdir $path/logs
fi

touch $path/logs/pi-hole-update-$timestamp.txt
echo "Pi updated on $timestamp" > $path/logs/pi-hole-update-$timestamp.txt
