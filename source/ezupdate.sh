#!/bin/zsh
#zypper refresh repos and update system

getpackagemanager

if [[ "$PACKAGE_MANAGER" == "zypper" ]]; then
  sudo zypper update -y 
elif [[ "$PACKAGE_MANAGER" == "dnf" ]]; then
  sudo dnf update -y
elif [[ "$PACKAGE_MANAGER" == "apt" ]]; then
  sudo apt update
  sudo apt upgrade -y
fi
