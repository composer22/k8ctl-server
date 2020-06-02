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

mkdir -p -m 777 /root/.aws
mkdir -p -m 777 /root/.kube

# Render and copy templates and configs to proper locations
envtpl -o /root/.aws/credentials -m error ./configmaps/aws-credentials
cp ./configmaps/aws-config /root/.aws/config

envtpl -o /root/.kube/config -m error ./configmaps/kubectl-config
envtpl -o .k8ctl-server.yml -m error ./configmaps/k8ctl-server-config

exec ./k8ctl-server start ${debug_flag}
