#!/bin/zsh
#gets systems package manager 

if which zypper &>/dev/null; then
  export PACKAGE_MANAGER="zypper" 
elif which dnf &>/dev/null; then
  export PACKAGE_MANAGER="dnf"
elif which apt &>/dev/null; then
  export PACKAGE_MANAGER="apt"
else
  echo "Error: Unsupported package manager"
  exit 1
fi
