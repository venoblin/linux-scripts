#!/bin/zsh
#activates venv at given location
location="venv/bin/activate"
if source $location; then
  echo "Activated"
fi