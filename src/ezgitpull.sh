#!/bin/bash
#pulls from current branch

current_branch=$(git symbolic-ref --short HEAD)

git pull origin $current_branch
