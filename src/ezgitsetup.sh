#!/bin/bash
#easy git setup on machine, creates an ssh key and returns it 

git config --global user.name "Your Name"
git config --global user.email "yourname@example.com"

git config --global init.defaultBranch main
git config --global color.ui auto
git config --global pull.rebase false

ssh-keygen -t ed25519
cat ~/.ssh/id_ed25519.pub
