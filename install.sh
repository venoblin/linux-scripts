#!/bin/zsh

if [ -d "bin/" ]; then
  echo "Bin directory already exists"
else
  echo "Installing..."
  echo "Creating bin directory"

  mkdir bin
  ./ezshc.sh

  source ~/.zshrc
fi