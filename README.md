# k8ctl-server

Server for limiting a subset of kubectl and helm features and commands.

Written in [Golang.](http://golang.org)

## Requirements

* An AWS admin account that has authority for SQS, Parameter Store.
* AWS authenticator + config file w/ access to AWS for use with EKS.
* kubectl and helm + those config files.
* Jenkins + webhook to handle deploy requests.

AWS parameter store is used:
* Validating API authentication tokens from the client.
* A list of valid applications that can be controlled by users.
* Retrieving Jenkins auth token for a deploy submission through a webhook.

All supporting binaries should be callable from the server's shell scripts.

## Command Line Usage

```
Server for managing a subset of commands w/ Kubernetes clusters.

Usage:
  k8ctl-server [command]

Available Commands:
  help        Help about any command
  start       Start the server
  version     Version of the application

Flags:
  -c, --config string   config file (default is $HOME/.k8ctl-server.yaml)
  -d, --debug           Enable debug
  -h, --help            help for k8ctl-server

Use "k8ctl-server [command] --help" for more information about a command.

```
## Configuration

A config file is mandatory. You can place it in the same directory as the
application or in your home directory. The name, with period, is:

.k8ctl-server.yaml


an example config file is included under /examples

### Building

This code currently requires version 1.14.1 or higher of Go.

. build.sh is the tool to create multiple executables. Edit what you need/don't need.

For package management, look to dep for instructions: <https://github.com/golang/dep>

commands:
```
dep init # only once.
dep ensure -add <another package>
dep ensure -update
dep status
```

Information on Golang installation, including pre-built binaries, is available at <http://golang.org/doc/install>.

Run `go version` to see the version of Go which you have installed.

Run `go build` inside the directory to build.

Run `go test ./...` to run the unit regression tests.

A successful build run produces no messages and creates an executable called `k8ctl-server` in this
directory.

Run `go help` for more guidance, and visit <http://golang.org/> for tutorials, presentations, references and more.

## Docker Image

```
# To build
 docker build --force-rm --no-cache --build-arg release_tag=1.0.0 -t composer22/k8ctl-server:1.0.0 .

# Configure as needed via docker-entrypoint.sh

## License

(The MIT License)

Copyright (c) 2020 Pyxxel Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
