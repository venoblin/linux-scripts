#!/bin/bash
#Turns all .sh files to binary then removes extension
#!/bin/bash
echo "Turning files into binaries..."
find . -type f -name "*.sh" -print0 | while IFS= read -r -d '' file; do
    shc -f $file
done

echo "Removing extensions..."
find . -type f -name "*.sh.x" -print0 | while IFS= read -r -d '' file; do
    echo ${file%.sh.x}
done

echo "Done!"


