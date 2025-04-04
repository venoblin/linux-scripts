#!/bin/bash
#updates Pi running Raspberry Pi OS, Pi-Hole, and Pi-VPN

sudo apt update
sudo apt upgrade -y

sudo pihole -g
sudo pihole -up
