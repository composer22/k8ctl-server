#!/usr/bin/env bash

# Rollback a release
export name=$1
export namespace=$2
export revision=$3

helm rollback ${name} ${revision} --namespace "${namespace}"

