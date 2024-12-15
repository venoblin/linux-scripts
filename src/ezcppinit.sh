#!/bin/bash
#initializes a cpp project

# mkdir $(pwd)/src

# touch $(pwd)/CMakeLists.txt
# echo 'cmake_minimum_required (VERSION 3.30.5)
# file (GLOB_RECURSE SOURCE_FILES "src/*.cpp")

# project (
#   projectname
#   VERSION "0.1.0"
#   DESCRIPTION "description"
#   LANGUAGES CXX
# )

# add_executable (projectname ${SOURCE_FILES})'> $(pwd)/CMakeLists.txt

# touch $(pwd)/build.sh
# echo '#!/bin/bash

# if ! [ -d "build" ]; then
#   mkdir build
# fi

# cd build/ && cmake ../ && make

# echo "Built engine in build directory."' > $(pwd)/build.sh

# touch $(pwd)/run.sh
# echo '#!/bin/bash

# if [ -d "build" ]; then
#   ./build/EmberEngine
# else
#   echo "No build found! Run build.sh first."
# fi ' > $(pwd)/run.sh

if [ ! -f ".gitignore" ]; then
  echo "no git ignore"
fi 