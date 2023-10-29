#!/bin/zsh

if [ -d "bin" ]; then
  echo "Bin directory already exists"
else
  echo "Installing..."
  mkdir bin
  ./ezshc.sh
fi