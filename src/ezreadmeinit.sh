#!/bin/bash
#initializes readme template at specified path

if [ -f "README.md" ]; then
  echo "Error: A README.md already in directory!"
  exit 1
fi 

readme_file="$HOME/dev/scripts/files/README.MD"

cp -r $readme_file $(pwd)