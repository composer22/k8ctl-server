#!/usr/bin/env bash

# Give the status of a release
export name=$1
export namespace=$2
export output=$3 # json or yaml or empty

if [ ! -z "$output" ]
then
   output="--output ${output}"
fi

helm status "${name}" --namespace "${namespace}" ${output}

