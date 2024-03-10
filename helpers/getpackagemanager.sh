#!/bin/zsh
#gets systems package manager 

if which zypper &>/dev/null; then
  package_manager="zypper" 
elif which dnf &>/dev/null; then
  package_manager="dnf"
elif which apt &>/dev/null; then
  package_manager="apt"
else
  echo "Error: Unsupported package manager"
  exit 1
fi
