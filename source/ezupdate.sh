#!/bin/zsh
#zypper refresh repos and update system

if which zypper &>/dev/null; then
  sudo zypper update -y 
elif which dnf &>/dev/null; then
  sudo dnf update -y
else
  echo "Unsupported package manager"
fi
