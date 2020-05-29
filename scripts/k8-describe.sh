#!/usr/bin/env bash

# Describe a resource from a namespace.
export resource_type=$1
export name=$2
export namespace=$3

kubectl describe ${resource_type} ${name} -n"${namespace}"


