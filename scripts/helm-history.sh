#!/usr/bin/env bash

# Give the history of a release
export name=$1
export output=$2 # json or yaml or empty

if [ ! -z "$output" ]
then
   output="--output ${output}"
fi

helm history $output "${name}"

