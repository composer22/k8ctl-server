#!/usr/bin/env bash

# Delete a release
export name=$1

helm delete --purge "${name}"

