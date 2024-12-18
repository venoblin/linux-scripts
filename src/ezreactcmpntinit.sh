#!/bin/bash
#creates a directory of a certain name with a jsx file and scss file with the same name

type="jsx"

if [[ ! "$1" ]]; then
  echo "Error: Path needed!" >&2
  exit 1
fi

if [[ "$2" == "-j" ]]; then
  type="jsx"
elif [[ "$2" == "-t" ]]; then
  type="tsx"
fi

mkdir $(pwd)/"$1"
touch $(pwd)/"$1"."$type"
echo "import './"$1".css'

const "$1" = () => {
  return (
    <div className='"$1"'>

    </div>
  )
}

export default "$1"" > $(pwd)/$1."$type"
touch $(pwd)/"$1".scss

mv $(pwd)/"$1".jsx $(pwd)/"$1"
mv $(pwd)/"$1".scss $(pwd)/"$1"