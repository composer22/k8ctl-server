#!/usr/bin/env bash

# Delete a release
export name=$1
export namespace=$2

helm delete "${name}" --namespace "${namespace}"

