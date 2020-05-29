#!/usr/bin/env bash

# List helm releases for a namespace
export namespace=$1
export output=$2 # json or yaml or empty

if [ ! -z "$output" ]
then
   output="--output ${output}"
fi

helm list -q --namespace "${namespace}" ${output}

