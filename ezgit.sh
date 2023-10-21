#!/bin/zsh
#push to main branch with commit message
if [[ ! -n $2 ]]; then
  if [[ -n $1 && ! $1 =~ [0-9] ]]; then
    git add .
    git commit -m "$1"
    git push origin main
  else
    echo "String needed for the message!"
  fi
  else echo "Too many arguments detected, only a message needed!"
fi