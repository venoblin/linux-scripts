#!/bin/zsh
#turns all scripts to binary, renames them, moves them to bin directory,
#and removes intermediate files
echo "Creating binaries and moving them to bin directory"
find . -type f -name "*.sh" -print0 | while IFS= read -r -d '' file; do
    if [[ $file != "./install.sh" ]]; then
        shc -f $file -o ${file%.sh}
        mv ${file%.sh} bin/
    fi
done

echo "Cleaning up"
find . -type f -name "*.sh.x.c" -print0 | while IFS= read -r -d '' file; do
    rm $file
done

echo "Done"

