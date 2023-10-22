#!/bin/zsh
#turns all scripts to binary, renames them, moves them to bin directory,
#and removes intermediate files
echo "Turning files to binary"
find . -type f -name "*.sh" -print0 | while IFS= read -r -d '' file; do
    shc -f $file
done

echo "Renaming binaries and moving to bin directory"
find . -type f -name "*.sh.x" -print0 | while IFS= read -r -d '' file; do
    mv $file ${file%.sh.x}
    mv ${file%.sh.x} bin/
done

echo "Cleaning up"
find . -type f -name "*.sh.x.c" -print0 | while IFS= read -r -d '' file; do
    rm $file
done

echo "Done"

