#!/bin/bash
#Turns all .sh files to binary then removes extension
#!/bin/bash
find . -type f -name "*.sh" -print0 | while IFS= read -r -d '' file; do
    echo $file
done

