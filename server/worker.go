package server

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/composer22/k8ctl-server/logger"
)

// NewWorker handles requests for deployments, rollbacks, and restarts.
type worker struct {
	done      chan bool                // Channel to receive signal to shutdown now.
	log       *logger.Logger           // Application log for events.
	opt       *Options                 // Server options.
	rcvParams *sqs.ReceiveMessageInput // Parameters for SQS client to use to receive a message.
	sqssvc    *sqs.SQS                 // Simple Queing Service.
	ssmsvc    *ssm.SSM                 // Parameter Store.
	wg        *sync.WaitGroup          // Wait group for the run.
}

// Represents the payload of a request to deploy a chart.
type DeployRequest struct {
	Name       string `json:"name"`       // The application/chart name to deploy.
	Namespace  string `json:"namespace"`  // The namespace to deploy.
	VersionTag string `json:"versionTag"` // The docker version tag.
}

// Represents the payload of a request to restart a deployment.
type RestartRequest struct {
	Namespace string `json:"namespace"` // The namespace to restart.
}

// Represents the payload of a request to rollack a chart.
type RollbackRequest struct {
	Revision string `json:"revision"` // The revision to roll back to (optional)
}

// NewWorker is a factory function that returns a worker object.
func NewWorker(done chan bool, logr *logger.Logger, options *Options, sqsc *sqs.SQS, ssmc *ssm.SSM, wtgrp *sync.WaitGroup) *worker {
	p := &sqs.ReceiveMessageInput{
		AttributeNames: []*string{
			aws.String(sqs.MessageSystemAttributeNameSentTimestamp),
		},
		MaxNumberOfMessages: aws.Int64(1),
		MessageAttributeNames: []*string{
			aws.String(sqs.QueueAttributeNameAll),
		},
		QueueUrl:          aws.String(options.QueueUrl),
		VisibilityTimeout: aws.Int64(int64(options.QueueVisibilityTimeout)),
		WaitTimeSeconds:   aws.Int64(int64(options.QueueWaitTimeInSeconds)),
	}
	return &worker{
		done:      done,
		log:       logr,
		opt:       options,
		rcvParams: p,
		sqssvc:    sqsc,
		ssmsvc:    ssmc,
		wg:        wtgrp,
	}
}

// Run is the main event loop that processes queued requests.
func (w *worker) Run() {
	w.wg.Add(1)
	defer w.wg.Done()
	for {
		select {
		case <-w.done: // Server signal quit
			return
		default:
			w.processQueue()
		}
		time.Sleep(time.Duration(w.opt.WorkerPollInt) * time.Second)
	}
}

// private methods.

// Checks the queue and processes a request if available.
func (w *worker) processQueue() {
	// Pop from queue
	job, err := w.sqssvc.ReceiveMessage(w.rcvParams) // TODO?
	if err != nil {
		w.log.Errorf("Receive message: %s", err.Error())
		return
	}

	// No messages. Bypass processing.
	if len(job.Messages) == 0 {
		return
	}

	// Delete message from queue after it's been received. (forced)
	defer func() {
		dmi := &sqs.DeleteMessageInput{
			QueueUrl:      aws.String(w.opt.QueueUrl),
			ReceiptHandle: job.Messages[0].ReceiptHandle,
		}
		if _, err := w.sqssvc.DeleteMessage(dmi); err != nil {
			w.log.Errorf("Delete message: %s", err.Error())
		}
	}()

	var jobType int
	attr := job.Messages[0].MessageAttributes["JobType"]
	if jobType, err = strconv.Atoi(aws.StringValue(attr.StringValue)); err != nil {
		w.log.Errorf("Could not retrieve job type: %s", err.Error())
		return
	}

	name := aws.StringValue(job.Messages[0].MessageAttributes["Name"].StringValue)
	payload := *job.Messages[0].Body

	// Process payload.
	switch jobType {
	case JobTypeDelete:
		w.delete(name)
	case JobTypeDeploy:
		w.deploy(payload)
	case JobTypeRestart:
		w.restart(name, payload)
	case JobTypeRollback:
		w.rollback(name, payload)
	default:
		w.log.Errorf("Jobtype: %d", jobType)
	}
	return
}

/************************************/
/************* ACTIONS **************/
/************************************/

// Delete a release.
func (w *worker) delete(name string) {
	cmd := exec.Command("./scripts/helm-delete.sh", name)
	result, err := execCmd(cmd)
	if err != nil {
		w.log.Errorf("helm-delete.sh: %s:%s", name, err.Error())
		return
	}
	w.log.Infof("Delete release %s %s", name, result)
}

// Multilayered request to Jenkins.
type JenkinsPayload struct {
	Metadata struct {
		App       string `json:"app"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Payload struct {
		Pushdata struct {
			Tag string `json:"tag"`
		} `json:"pushdata"`
		Repository struct {
			RepoName string `json:"repo_name"`
		} `json:"repository"`
		CallbackUrl string `json:"callback_url"`
	} `json:"payload"`
}

// Deploy a release.
func (w *worker) deploy(body string) {
	var req DeployRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		w.log.Errorf("Unmarshal release: %s error: %s", body, err.Error())
		return
	}

	// Call Jenkins

	// Retrieve the Jenkin's token from AWS.
	t, err := w.ssmsvc.GetParameter(
		&ssm.GetParameterInput{
			Name:           aws.String(w.opt.JenkinsTokenPath),
			WithDecryption: aws.Bool(true),
		})
	if err != nil {
		w.log.Errorf("Unable to retrieve Jenkins token. Error: %s", err.Error())
		return
	}
	token := aws.StringValue(t.Parameter.Value)

	// target-host: http://jenkins
	// target-port: 80
	// target-path: /generic-webhook-trigger/invoke

	// Create the new payload and request to forward.
	// Jenkins job params:
	// $.payload.push_data.tag
	// $.payload.repository.repo_name
	// $.payload.callback_url
	// $.metadata.namespace
	p := &JenkinsPayload{}
	p.Metadata.App = applicationName
	p.Metadata.Namespace = req.Namespace
	p.Payload.Pushdata.Tag = req.VersionTag
	p.Payload.Repository.RepoName = req.Name
	p.Payload.CallbackUrl = ""
	pj, _ := json.Marshal(p)
	payload := []byte(pj)

	var out *http.Request
	if out, err = http.NewRequest("POST", w.opt.JenkinsUrl, bytes.NewBuffer(payload)); err != nil {
		w.log.Errorf("Could not create new request to jenkins: %s", err.Error())
		return
	}

	// Set headers and query string
	out.Header.Set("Content-Type", "application/json")
	q := out.URL.Query()
	q.Add("token", token)
	out.URL.RawQuery = q.Encode()

	// Send it downrange.
	cl := &http.Client{}
	var resp *http.Response
	if resp, err = cl.Do(out); err != nil {
		w.log.Errorf("Could not send a new request to jenkins: '%s'", err.Error())
		return
	}

	// Decode the response.
	if resp.StatusCode != http.StatusOK {
		w.log.Errorf("Could not depoly %s:%s/%s - %s", req.Name, req.VersionTag, req.Namespace)
		return
	}

	defer resp.Body.Close()
	var b []byte
	if b, err = ioutil.ReadAll(resp.Body); err != nil {
		w.log.Errorf("Could not read body of deploy response: %s", err.Error())
		return
	}
	rbody := string(b)
	w.log.Infof("Deploy release %s:%s/%s - %s", req.Name, req.VersionTag, req.Namespace, rbody)
}

// Restart a deployment.
func (w *worker) restart(name string, body string) {
	var req RestartRequest
	err := json.Unmarshal([]byte(body), &req)
	if err != nil {
		w.log.Errorf("Unmarshal %s %s %s", name, body, err.Error())
		return
	}
	cmd := exec.Command("./scripts/k8-restart.sh", name, req.Namespace)
	var result string
	result, err = execCmd(cmd)
	if err != nil {
		w.log.Errorf("k8-restart.sh: %s/%s %s", name, req.Namespace, err.Error())
		return
	}
	w.log.Infof("Restart deployment %s/%s : %s", name, req.Namespace, result)
}

// Rollback a release.
func (w *worker) rollback(name string, body string) {
	var req RollbackRequest
	err := json.Unmarshal([]byte(body), &req)
	if err != nil {
		w.log.Errorf("Rollback release %s: %s", name, err.Error())
		return
	}

	cmd := exec.Command("./scripts/k8-restart.sh", name, req.Revision)
	var result string
	result, err = execCmd(cmd)
	if err != nil {
		w.log.Errorf("k8-restart.sh: %s/%s %s", name, req.Revision, err.Error())
		return
	}
	w.log.Infof("Rollback release %s/%s : %s", name, req.Revision, result)
}
