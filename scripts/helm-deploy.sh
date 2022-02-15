#!/usr/bin/env bash

# Deploy a release
name=$1  # ex foo/bar-chart
image_tag=$2 # ex 1.0.0
namespace=$3 # ex dev
company_prefix=$4 # ex widcom

cd /tmp/helm-deploy-charts

# Get the service name
chart_name=$(grep  "^name:" ./${name}/Chart.yaml | awk '{print $2}')

# Deploy chart
helm upgrade ${company_prefix}-${chart_name}-${namespace} \
--install \
--force \
--namespace ${namespace} \
--set image.tag=${image_tag} \
./${name}/

cd -
