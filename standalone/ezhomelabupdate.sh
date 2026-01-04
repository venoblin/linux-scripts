#!/bin/bash
#Updates homelab and also syncs snapraid

if which zypper &>/dev/null; then
  sudo zypper ref
  sudo zypper update -y  
elif which dnf &>/dev/null; then
  sudo dnf upgrade --refresh -y
  sudo dnf update -y
elif which apt &>/dev/null; then
  sudo apt update
  sudo apt upgrade -y
else
  echo "Error: Unsupported package manager"
  exit 1
fi

sudo snapraid sync