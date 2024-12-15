#!/bin/bash
#initializes a cpp project

project_name="$1"
if [[ -z "$1" ]]; then
  echo "Error: project name needed." >&2
  exit 1
fi

mkdir $(pwd)/src
touch $(pwd)/src/main.cpp
echo "#include <iostream>

int main() {

  std::cout << \"Hello World!\" << std::endl;

  return 0;
}" > $(pwd)/src/main.cpp

touch $(pwd)/CMakeLists.txt
echo "cmake_minimum_required (VERSION 3.30.5)
file (GLOB_RECURSE SOURCE_FILES \"src/*.cpp\")

project (
  "$project_name"
  VERSION \"0.1.0\"
  DESCRIPTION \"description\"
  LANGUAGES CXX
)

add_executable ("$project_name" \${SOURCE_FILES})"> $(pwd)/CMakeLists.txt

touch $(pwd)/build.sh
chmod +x build.sh
echo "#!/bin/bash

if ! [ -d \"build/\" ]; then
  mkdir build
fi

cd build/ && cmake ../ && make

echo \"Built "$project_name" in build directory.\"" > $(pwd)/build.sh

touch $(pwd)/run.sh
chmod +x run.sh
echo "#!/bin/bash

if [ -d \"build/\" ]; then
  ./build/"$project_name"
else
  echo \"Error: No build found! Run build.sh first.\"
fi" > $(pwd)/run.sh


ignore='.vscode/
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
Ogre.log'
if [ ! -f ".gitignore" ]; then
  touch $(pwd)/.gitignore

  echo -e "$ignore" > $(pwd)/.gitignore
else
  echo -e "$ignore" >> $(pwd)/.gitignore
fi 

if [ ! -f "README.md" ]; then
  touch $(pwd)/.README.md

  echo "# "$project_name"" > $(pwd)/.README.md
fi 
