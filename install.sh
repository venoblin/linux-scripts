#!/bin/zsh

if [ -d "bin/" ]; then
  echo "Bin directory already exists"
else
  echo "Installing..."
  
  echo "Creating bin directory"
  mkdir bin

  echo "Writing to zshrc file"
  bin_location="$(pwd)/bin"
  zshrc_file="$HOME/.zshrc"
  
  if ! grep -q "export PATH.*$bin_location" $zshrc_file; then
    echo 'export PATH="$PATH:'"$bin_location"'"' | cat - "$zshrc_file" > temp && mv temp "$zshrc_file"
  fi
  
  ./ezshc.sh
fi

