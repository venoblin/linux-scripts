#!/bin/zsh
#zypper refresh repos and update system

if which zypper &>/dev/null; then
  sudo zypper update -y 
elif which dnf &>/dev/null; then
  sudo dnf update -y
elif which apt &>/dev/null; then
  sudo apt update
  sudo apt upgrade -y
else
  echo "Unsupported package manager"
fi
