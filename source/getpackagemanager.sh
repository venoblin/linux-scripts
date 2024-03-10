#!/bin/zsh
#gets systems package manager 

if which zypper &>/dev/null; then
  PACKAGE_MANAGER="zypper" 
elif which dnf &>/dev/null; then
  PACKAGE_MANAGER="dnf"
elif which apt &>/dev/null; then
  PACKAGE_MANAGER="apt"
else
  echo "Error: Unsupported package manager"
  exit 1
fi

export $PACKAGE_MANAGER