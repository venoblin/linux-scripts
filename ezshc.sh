#!/bin/bash
#turns all .sh files to binary then removes extension
echo "Turning files to binary"
find . -type f -name "*.sh" -print0 | while IFS= read -r -d '' file; do
    shc -f $file
done

echo "Removing extensions"
find . -type f -name "*.sh.x" -print0 | while IFS= read -r -d '' file; do
    mv $file ${file%.sh.x}
done

echo "Done!"


