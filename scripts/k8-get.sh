#!/usr/bin/env bash

# Get a list of resources from a namespace.
export resource_type=$1
export namespace=$2
export output=$3 # json or yaml or empty

if [ ! -z "$output" ]
then
   output="--output ${output}"
fi

kubectl get ${resource_type} -n"${namespace}" ${output}

