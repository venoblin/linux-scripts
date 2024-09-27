#!/bin/bash

if [ -d "bin/" ]; then
  rm -rf bin/
fi

#checking if shc is installed and giving user choice to install it
if ! command -v shc &> /dev/null; then
  echo "Shc is necessary and is not installed."
  echo "Do you wish to install it? [Y, n]"
  read -r

  #empty response (enter key) default is y
  if [ -z "$REPLY" ]; then
    REPLY="y"
  fi

  #yes or no response case sensitive
  if [[ "$REPLY" =~ ^[Yy]$ ]]; then
    if which zypper &>/dev/null; then
      sudo zypper install shc gcc
    elif which dnf &>/dev/null; then
      sudo dnf install shc gcc-c++
    elif which apt &>/dev/null; then
      sudo apt install shc gcc
    else
      echo "Error: Unsupported package manager"
      exit 1
    fi
  elif [[ "$REPLY" =~ ^[Nn]$ ]]; then
    echo "Exiting..."
    exit 0
  else
    echo "Invalid input."
  fi
fi

echo "Installing..."

echo "Creating bin directory."
mkdir bin

echo "Writing to zshrc file."
bin_location="$(dirname "$0")/bin"
zshrc_file="$HOME/.zshrc"
if ! grep -q "export PATH.*$bin_location" $zshrc_file; then
  echo 'export PATH="'"$bin_location"':$PATH"' | cat - "$zshrc_file" > temp && mv temp "$zshrc_file"
fi

./src/ezshc.sh


