#!/bin/bash

set -eo pipefail
if [ -n "$LOG_LEVEL" ] && [ "$LOG_LEVEL" == "trace" ]
then
  set -xeo pipefail
fi

if [ "$LOG_LEVEL" == "debug" ] || [ "$LOG_LEVEL" == "trace" ]
then
  debug_flag="-d"
  echo "============== Environment =============="
  env | sort
  echo "========================================="
fi

# we're in /usr/local/docker/k8ctl-server/

mkdir -p -m 777 .aws
mkdir -p -m 777 .kube

# Render templates to config locations
envtpl -o .aws/credentials -m error ./configmaps/aws-credentials/credentials
envtpl -o .kube/config -m error ./configmaps/kubectl-config/config

exec k8ctl-server start ${debug_flag}
