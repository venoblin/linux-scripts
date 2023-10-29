#!/bin/zsh
#zypper refresh repos and update system

if which zypper &>/dev/null; then
  sudo zypper ref
  sudo zypper update -y 
elif which dnf &>/dev/null; then
  sudo dnf check-update
  sudo dnf update
else
  echo "Unsupported package manager"
fi
