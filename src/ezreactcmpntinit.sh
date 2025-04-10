#!/bin/bash
#creates a directory of a certain name with a jsx file and scss file with the same name

type="jsx"

if [[ ! "$#" -eq 2 ]]; then
  echo "Error: Component name and path needed!" >&2
  exit 1
fi

if [[ "$3" == "-j" ]]; then
  type="jsx"
elif [[ "$3" == "-t" ]]; then
  type="tsx"
fi

mkdir "$2"/"$1"
touch "$2"/"$1"."$type"
echo "import './"$1".css'

const "$1" = () => {
  return (
    <div className='"$1"'>

    </div>
  )
}

export default "$1"" > "$2"/$1."$type"

touch "$2"/"$1".scss
