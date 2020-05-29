#!/usr/bin/env bash

# Restart a deployment
export name=$1
export namespace=$2

kubectl -n ${namespace} rollout restart deployment ${name}
