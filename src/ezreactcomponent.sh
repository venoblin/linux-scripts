#!/bin/bash
#creates a directory of a certain name with a jsx file and scss file with the same name

mkdir $(pwd)/$1
touch $(pwd)/$1.jsx
touch $(pwd)/$1.scss

mv $(pwd)/$1.jsx $(pwd)/$1
mv $(pwd)/$1.scss $(pwd)/$1