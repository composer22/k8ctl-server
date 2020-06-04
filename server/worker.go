package server

import (
	"bytes"
	"encoding/json"
	"fmt"
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
		QueueUrl:          &options.QueueUrl,
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
	job, err := w.sqssvc.ReceiveMessage(w.rcvParams)
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
	user := aws.StringValue(job.Messages[0].MessageAttributes["User"].StringValue)
	payload := *job.Messages[0].Body

	// Process payload.
	switch jobType {
	case JobTypeDelete:
		w.delete(user, name)
	case JobTypeDeploy:
		w.deploy(user, payload)
	case JobTypeRestart:
		w.restart(user, name, payload)
	case JobTypeRollback:
		w.rollback(user, name, payload)
	default:
		w.log.Errorf("Jobtype: %d", jobType)
	}
	return
}

/************************************/
/************* ACTIONS **************/
/************************************/

// Delete a release.
func (w *worker) delete(user string, name string) {
	cmd := exec.Command("./scripts/helm-delete.sh", name)
	result, err := execCmd(cmd)
	if err != nil {
		w.log.Errorf("helm-delete.sh: %s:%s", name, err.Error())
		w.sendSlack("danger", user, "delete", name, ":ghost:", "", "*Error*: Could not delete release.")
		return
	}
	w.log.Infof("Delete release %s %s", name, result)
	w.sendSlack("good", user, "delete", name, ":thumbsup:", "", "*Success*: Release deleted.")
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
		} `json:"push_data"`
		Repository struct {
			RepoName string `json:"repo_name"`
		} `json:"repository"`
		CallbackUrl string `json:"callback_url"`
	} `json:"payload"`
}

// Deploy a release.
func (w *worker) deploy(user string, body string) {
	var req DeployRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		w.log.Errorf("Unmarshal release: %s error: %s", body, err.Error())
		w.sendSlack("danger", user, "deploy", "(unknown target)", ":ghost:", "(unknown)", "*Error*: Could not Unmarshal request.")
		return
	}
	name := fmt.Sprintf("%s:%s", req.Name, req.VersionTag)

	// Call Jenkins

	// Retrieve the Jenkin's token from AWS.
	t, err := w.ssmsvc.GetParameter(
		&ssm.GetParameterInput{
			Name:           aws.String(w.opt.JenkinsTokenPath),
			WithDecryption: aws.Bool(true),
		})
	if err != nil {
		w.log.Errorf("Unable to retrieve Jenkins token. Error: %s", err.Error())
		w.sendSlack("danger", user, "deploy", name, ":ghost:", req.Namespace, "*Error*: Could not retrieve auth to Jenkins.")
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
	payload, _ := json.Marshal(p)

	var out *http.Request
	if out, err = http.NewRequest("POST", w.opt.JenkinsUrl, bytes.NewBuffer(payload)); err != nil {
		w.log.Errorf("Could not create new request to jenkins: %s", err.Error())
		w.sendSlack("danger", user, "deploy", name, ":ghost:", req.Namespace, "*Error*: Could not create request to Jenkins.")
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
		w.sendSlack("danger", user, "deploy", name, ":ghost:", req.Namespace, "*Error*: Could not send request to Jenkins.")
		return
	}

	defer resp.Body.Close()
	var b []byte
	if b, err = ioutil.ReadAll(resp.Body); err != nil {
		w.log.Errorf("Could not read body of deploy response: %s", err.Error())
		w.sendSlack("danger", user, "deploy", name, ":ghost:", req.Namespace, "*Error*: Could not read response from Jenkins.")
		return
	}
	rbody := string(b)

	// Validate the response.
	if resp.StatusCode != http.StatusOK {
		w.log.Errorf("Could not deploy %s:%s/%s - %n %s", req.Name, req.VersionTag, req.Namespace, resp.StatusCode, rbody)
		w.sendSlack("danger", user, "deploy", name, ":ghost:", req.Namespace, "*Error*: Invalid response from Jenkins.")
		return
	}

	w.log.Infof("Deploy release %s:%s/%s - %s", req.Name, req.VersionTag, req.Namespace, rbody)
	w.sendSlack("good", user, "deploy", name, ":thumbsup:", req.Namespace, "*Success*: Release deployed to Jenkins.")

}

// Restart a deployment.
func (w *worker) restart(user string, name string, body string) {
	var req RestartRequest
	err := json.Unmarshal([]byte(body), &req)
	if err != nil {
		w.log.Errorf("Unmarshal %s %s %s", name, body, err.Error())
		w.sendSlack("danger", user, "restart", name, ":ghost:", "(unknown)", "*Error*: Could not unmarshal request.")
		return
	}
	cmd := exec.Command("./scripts/k8-restart.sh", name, req.Namespace)
	var result string
	result, err = execCmd(cmd)
	if err != nil {
		w.log.Errorf("k8-restart.sh: %s/%s %s", name, req.Namespace, err.Error())
		w.sendSlack("danger", user, "restart", name, ":ghost:", req.Namespace, "*Error*: Could not restart.")
		return
	}
	w.log.Infof("Restart deployment %s/%s : %s", name, req.Namespace, result)
	w.sendSlack("good", user, "restart", name, ":thumbsup:", req.Namespace, "*Success*: Deployment restarted.")
}

// Rollback a release.
func (w *worker) rollback(user string, name string, body string) {
	var req RollbackRequest
	err := json.Unmarshal([]byte(body), &req)
	if err != nil {
		w.log.Errorf("Rollback release %s: %s", name, err.Error())
		w.sendSlack("danger", user, "rollback", name, ":ghost:", "", "*Error*: Could not unmarshal request.")
		return
	}

	cmd := exec.Command("./scripts/helm-rollback.sh", name, req.Revision)
	var result string
	result, err = execCmd(cmd)
	if err != nil {
		w.log.Errorf("k8-restart.sh: %s/%s %s", name, req.Revision, err.Error())
		w.sendSlack("danger", user, "rollback", name, ":ghost:", "", fmt.Sprintf("*Error*: Could not rollback release %s.", req.Revision))
		return
	}
	w.log.Infof("Rollback release %s/%s : %s", name, req.Revision, result)
	w.sendSlack("good", user, "rollback", name, ":thumbsup:", "", fmt.Sprintf("*Success*: Release rolledback to %s", req.Revision))
}

// Send slack message
func (w *worker) sendSlack(color string, user string, action string,
	target string, icon string, namespace string, message string) {

	// Optional namespace
	var ns string
	if namespace != "" {
		ns = fmt.Sprintf("namespace: %s\n", namespace)
	}

	// Create the payload.
	messageLong := fmt.Sprintf("%s/%s:\t%s %s\n%sresult: %s", user, action, target, icon, ns, message)
	tmpl := `{"attachments": [{
    "fallback": "%s",
    "color": "%s",
    "mrkdwn_in": ["text","fields"],
    "text": "%s",
     }]}`
	payload := fmt.Sprintf(tmpl, message, color, messageLong)

	// Send the request.
	req, err := http.NewRequest(httpPost, w.opt.SlackUrl, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		w.log.Errorf("Slack NewRequest: %s", err.Error())
		return

	}
	cl := &http.Client{}
	_, err = cl.Do(req)
	if err != nil {
		w.log.Errorf("Slack send msg: %s", err.Error())
	}
}
