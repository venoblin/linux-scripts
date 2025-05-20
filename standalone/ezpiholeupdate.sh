#!/bin/bash
#updates Pi running Raspberry Pi OS, Pi-Hole, and Pi-VPN

sudo apt update
sudo apt upgrade -y

sudo pihole -g
sudo pihole -up

path="/home/jvhmx/dev/linux-scripts"
timestamp=$(date "+%Y-%m-%d_%H:%M:%S")
file="pi-hole-update-logs.txt"

if [ ! -d "$path/logs" ]; then
  mkdir $path/logs
  sudo chown jvhmx $path/logs
fi

if [ ! -f "$path/logs/$file" ]; then
  touch $path/logs/$file
  sudo chown jvhmx $path/logs/$file
fi

echo "Pi updated: $timestamp" >> $path/logs/$file
echo "" >> $path/logs/$file
