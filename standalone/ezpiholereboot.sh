#!/bin/bash
#Easily reboots PI device

path="/home/jvhmx/dev/linux-scripts"
timestamp=$(date "+%Y-%m-%d_%H:%M:%S")
file="pi-hole-logs.txt"

if [ ! -d "$path/logs" ]; then
  mkdir $path/logs
  sudo chown jvhmx $path/logs
fi

if [ ! -f "$path/logs/$file" ]; then
  touch $path/logs/$file
  sudo chown jvhmx $path/logs/$file
fi

echo "Pi rebooted: $timestamp" >> $path/logs/$file

sudo shutdown -r now
