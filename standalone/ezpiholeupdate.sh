#!/bin/bash
#updates Pi running Raspberry Pi OS, Pi-Hole, and Pi-VPN

#sudo apt update
#sudo apt upgrade -y

#sudo pihole -g
#sudo pihole up

path="/home/jvhmx/dev/linux-scripts"
timestamp=$(date "+%Y-%m-%d_%H:%M:%S")
name="pi-hole-update"

if [ ! -d "$path/logs" ]; then
  mkdir $path/logs
  sudo chown jvhmx $path/logs
fi

touch $path/logs/$name-$timestamp.txt
echo "Pi updated on $timestamp" > $path/logs/$name-$timestamp.txt
sudo chown jvhmx $path/logs/$name-$timestamp.txt
