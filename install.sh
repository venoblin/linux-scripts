#!/bin/zsh

if [ -d "bin/" ]; then
  rm -rf bin/
fi

echo "Installing..."

echo "Creating bin directory"
mkdir bin

echo "Writing to zshrc file"
bin_location="$(pwd)/bin"
zshrc_file="$HOME/.zshrc"
if ! grep -q "export PATH.*$bin_location" $zshrc_file; then
  echo 'export PATH="'"$bin_location"':$PATH"' | cat - "$zshrc_file" > temp && mv temp "$zshrc_file"
fi

./ezshc.sh


