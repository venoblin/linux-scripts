#!/bin/zsh
#gets systems package manager 

if which zypper &>/dev/null; then
  echo "zypper" 
elif which dnf &>/dev/null; then
  echo "dnf"
elif which apt &>/dev/null; then
  echo "apt"
else
  echo "Error: Unsupported package manager"
  exit 1
fi