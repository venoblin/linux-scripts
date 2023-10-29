#!/bin/zsh

if [ -d "bin" ]; then
  echo "Bin directory already exists"
else
  mkdir bin
  ./ezshc.sh
fi