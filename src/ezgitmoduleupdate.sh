#!/bin/bash
#updates submodules at current working directory

git submodule update --init --recursive
git submodule update --recursive --remote