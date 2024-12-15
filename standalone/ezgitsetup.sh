#!/bin/bash
#easy git setup on machine, creates an ssh key and returns it 

if [[ ! -n $2 ]]; then
  echo "Error: name and email required." >&2
  exit 1
fi

git config --global user.name $1
git config --global user.email $2

git config --global init.defaultBranch main
git config --global color.ui auto
git config --global pull.rebase false

ssh-keygen -t ed25519
cat ~/.ssh/id_ed25519.pub
