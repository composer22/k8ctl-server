#!/usr/bin/env bash

# Give the history of a release
export name=$1
export namespace=$2
export output=$3 # json or yaml or empty

if [ ! -z "$output" ]
then
   output="--output ${output}"
fi

helm history "${name}" --namespace "${namespace}" $output

