#!/bin/bash
#initializes readme template at specified path

scripts_location=$(dirname $(dirname $(command -v ezreadmeinit)))
readme_file="$scripts_location/files/README.md"

if [ -f "README.md" ]; then
  echo "Error: A README.md already in directory!" >&2
  exit 1
fi 

cp -r $readme_file $(pwd)
