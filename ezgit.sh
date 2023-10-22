#!/bin/zsh
#push to main branch with commit message
if [[ ! -n $2 ]]; then
  if [[ -n $1 && ! $1 =~ [0-9] ]]; then
    git add .
    git commit -m "$1"
    git push origin main
  else
    echo "Error: string needed for the message" >&2
  fi
  else echo "Error: too many arguments detected, only a message needed" >&2
fi