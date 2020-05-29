#!/usr/bin/env bash

# Rollback a release
export name=$1
export revision=$2

helm rollback ${name} ${revision}

