#!/bin/zsh
#zypper refresh repos and update system

source $(dirname "$0")/../helpers/getpackagemanager.sh


if [[ $PACKAGE_MANAGER == "zypper" ]]; then
  sudo zypper update -y 
elif [[ $PACKAGE_MANAGER == "dnf" ]]; then
  sudo dnf update -y
elif [[ $PACKAGE_MANAGER == "apt" ]]; then
  sudo apt update
  sudo apt upgrade -y
else
  echo "Unsupported package manager"
fi
