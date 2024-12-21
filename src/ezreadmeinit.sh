#!/bin/bash
#initializes readme template at specified path

scripts_location=$(dirname $(dirname $(command -v ezreadmeinit)))
readme_file="$scripts_location/files/README.md"
project_logo="$scripts_location/files/project-logo.png"

if [ -f "README.md" ]; then
  echo "Error: A README.md already in directory!" >&2
  exit 1
fi 

cp -r "$readme_file" $(pwd)
mkdir $(pwd)/.project-images
cp -r "$project_logo" $(pwd)/.project-images