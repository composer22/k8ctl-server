#!/usr/bin/env bash

# Example for updating the parameter store:

# User auth
aws ssm put-parameter --name "/your-company.com/k8ctl-server/auth/MCcwRdbxoxHWThDzmnNXfrMgTlvMGqW5/token" --value "e7Do7X43PR6WcYPWKPf874SvEwvPJCA5" --type SecureString
aws ssm put-parameter --name "/your-company.com/k8ctl-server/auth/MCcwRdbxoxHWThDzmnNXfrMgTlvMGqW5/name" --value "Sally" --type String

# Valid apps
valid_apps_query="app1-server,app2-service,app2-website"
valid_apps_deploy="app1-server,app2"

aws ssm put-parameter --name "/your-company.com/k8ctl-server/valid-apps/query" --value "${valid_apps_query}" --type StringList
aws ssm put-parameter --name "/your-company.com/k8ctl-server/valid-apps/deploy" --value "${valid_apps_deploy}" --type StringList
