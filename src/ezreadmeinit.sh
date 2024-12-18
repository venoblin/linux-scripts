#!/bin/bash
#initializes readme template at specified path

if [ -f "README.md" ]; then
  echo "Error: A README.md already in directory!"
  exit 1
fi 

scripts_location=$(dirname $(dirname $(command -v ezreadmeinit)))
readme_file="$scripts_location/files/README.md"

cp -r $readme_file $(pwd)
