#!/usr/bin/env bash

# Sync git repo for charts to deploy.
git_repo=$1 # ex github/widcom/mycharts

# create tmp directory
mkdir -p /tmp/helm-deploy-charts
cd /tmp/helm-deploy-charts

if [ ! -d "/tmp/helm-deploy-charts/.git" ]; then
    # if .git directory is not there, clone master
	git clone https://${git_repo} /tmp/helm-deploy-charts
else
    # else pull master
	git pull origin master
fi

cd -
