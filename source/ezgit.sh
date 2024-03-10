#!/bin/zsh
#push to current branch with commit message

current_branch=$(git symbolic-ref --short HEAD)

if [[ ! -n $2 ]]; then
  if [[ -n $1 && ! $1 =~ [0-9] ]]; then
    git add .
    git commit -m "$1"
    git push origin $current_branch
  else
    echo "Error: string needed for the message." >&2
    exit 1
  fi
  else echo "Error: too many arguments detected, only a message needed." >&2
  exit 1
fi
