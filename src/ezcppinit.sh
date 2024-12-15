#!/bin/bash
#initializes a cpp project

mkdir $(pwd)/src

touch $(pwd)/CMakeLists.txt
echo 'cmake_minimum_required (VERSION 3.30.5)
file (GLOB_RECURSE SOURCE_FILES "src/*.cpp")

project (
  projectname
  VERSION "0.1.0"
  DESCRIPTION "description"
  LANGUAGES CXX
)

add_executable (projectname ${SOURCE_FILES})'> $(pwd)/CMakeLists.txt

touch $(pwd)/build.sh
echo '#!/bin/bash

if ! [ -d "build" ]; then
  mkdir build
fi

cd build/ && cmake ../ && make

echo "Built engine in build directory."' > $(pwd)/build.sh

touch $(pwd)/run.sh
echo '#!/bin/bash

if [ -d "build" ]; then
  ./build/EmberEngine
else
  echo "No build found! Run build.sh first."
fi ' > $(pwd)/run.sh

if [ ! -f ".gitignore" ]; then
  touch $(pwd)/.gitignore

  echo 'build/
  .vscode/
  *.DS_STORE
  .ycm_extra_conf.*
  CMakeCache.txt
  CMakeFiles/
  CMakeScripts/
  *.cmake
  build/
  xcode_build/
  *.swp
  obj/
  *.a
  *.o
  *.data
  tags
  tmp/
  Makefile
  .clangd/
  compile_commands.json
  .cache/
  Ogre.log' > $(pwd)/.gitignore
else
  echo 'build/
  .vscode/
  *.DS_STORE
  .ycm_extra_conf.*
  CMakeCache.txt
  CMakeFiles/
  CMakeScripts/
  *.cmake
  build/
  xcode_build/
  *.swp
  obj/
  *.a
  *.o
  *.data
  tags
  tmp/
  Makefile
  .clangd/
  compile_commands.json
  .cache/
  Ogre.log' >> $(pwd)/.gitignore
fi 

if [ ! -f "README.md" ]; then
  touch $(pwd)/.README.md

  echo '# Project name' > $(pwd)/.README.md
fi 
