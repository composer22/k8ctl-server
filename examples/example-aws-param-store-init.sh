#!/usr/bin/env bash

# Example for updating the parameter store:

# AWS Creds
aws ssm put-parameter --name "/your-company.com/k8ctl-server/aws/access_key_id" --value "GUq0ts8M7rkptkka4em6JWmDKjAEQVdn" --type SecureString
aws ssm put-parameter --name "/your-company.com/k8ctl-server/aws/secret_access_key" --value "EHhS37jbIme7B16" --type SecureString

# User auth
aws ssm put-parameter --name "/your-company.com/k8ctl-server/auth/DzmnNXfrMgTlv/token" --value "e7Do7X43PR6WcYPWKPf874SvEwvPJCA5" --type SecureString
aws ssm put-parameter --name "/your-company.com/k8ctl-server/auth/DzmnNXfrMgTlv/name" --value "Sally" --type String

# Jenkins Token
aws ssm put-parameter --name "/your-company.com/k8ctl-server/jenkins/webhook/deploy-token" --value "blabla" --type SecureString

# Healthcheck
aws ssm put-parameter --name "/your-company.com/k8ctl-server/path-alive" --value "/healthymonkey" --type SecureString

# Slack Path
aws ssm put-parameter --name "/your-company.com/k8ctl-server/path-slack" --value "Loo/dee/daaa" --type SecureString

# Slack Classic API Token
aws ssm put-parameter --name "/your-company.com/k8ctl-server/slack/user-token" --value "xoxp-meow" --type SecureString
aws ssm put-parameter --name "/your-company.com/k8ctl-server/slack/bottle" --value "xoxb-purrrr" --type SecureString
aws ssm put-parameter --name "/your-company.com/k8ctl-server/slack/signer" --value "grrrr" --type SecureString

# Valid apps
valid_apps_query="app1-server,app2-service,app2-website"
valid_apps_deploy="app1-server,app2"

aws ssm put-parameter --name "/your-company.com/k8ctl-server/valid-apps/query" --value "${valid_apps_query}" --type StringList
aws ssm put-parameter --name "/your-company.com/k8ctl-server/valid-apps/deploy" --value "${valid_apps_deploy}" --type StringList

