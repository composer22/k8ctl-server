package server

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/spf13/viper"
)

// Options represents parameters that are passed to the application for launching the server.
type Options struct {
	AuthPathPrefix         string        `json:"authPathPrefix"`      // Path in ssm to locate user key for authentication. /<prefix>/:user/token/
	ConfigPrefix           string        `json:"configPrefix"`        // Prefix of the config file name of the server.
	Debug                  bool          `json:"debugEnabled"`        // Is debugging enabled for the server?
	HealthRoute            string        `json:"healthRoute"`         // Obuscated route to the heathcheck of the server.
	Hostname               string        `json:"hostName"`            // Hostname of the server.
	JenkinsUrl             string        `json:"jenkinsUrl"`          // Endpoint to jenkins ingest webhook. This is within K8s.
	JenkinsTokenPath       string        `json:"jenkinsTokenPath"`    // Path in ssm to retrieve the token to make API calls to Jenkins server.
	Namespaces             []string      `json:"namespaces"`          // Namespaces this server manages.
	Port                   int           `json:"port"`                // HTTP api port of the server.
	ProfPort               int           `json:"profPort"`            // The profiler port of the server.
	QueueUrl               string        `json:"queueUrl"`            // URL to the queue server.
	QueueVisibilityTimeout int           `json:"queueTimeout"`        // How long the message should be hidden after receive.
	QueueWaitTimeInSeconds int           `json:"queueWait"`           // How long to wait for a message to be available.
	ReadTimeout            time.Duration `json:"readTimeout"`         // Server read request timeout.
	ShutdownWait           time.Duration `json:"shutdownWait"`        // Shutdown wait time in seconds.
	SlackUrl               string        `json:"slackUrl"`            // Url of the webhook to slack channel for reporting.
	ValidAppsQueryPath     string        `json:"validAppsQueryPath"`  // Path in ssm to validate applications that can be queries by the server.
	ValidAppsDeployPath    string        `json:"validAppsDeployPath"` // Path in ssm to validate applications that can be deployed by the server.
	WorkerPollInt          int           `json:"workerPoll"`          // Worker poll wait interval.
	WriteTimeout           time.Duration `json:"writeTimeout"`        // Server write request timeout.
}

// Factory function to create Option objects.
func NewOptions(debug bool) *Options {
	o := &Options{Debug: debug}
	o.FillConfig()
	return o
}

// Fill in the options from a viper configuration.
func (o *Options) FillConfig() {
	o.AuthPathPrefix = viper.GetString("auth_path_prefix")
	o.HealthRoute = viper.GetString("health_route")
	o.Hostname = viper.GetString("host_name")
	o.JenkinsUrl = viper.GetString("jenkins_url")
	o.JenkinsTokenPath = viper.GetString("jenkins_token_path")
	o.Namespaces = viper.GetStringSlice("namespaces")
	sort.Strings(o.Namespaces)
	o.Port = viper.GetInt("port")
	o.ProfPort = viper.GetInt("profiler_port")
	o.QueueUrl = viper.GetString("queue_url")
	o.QueueVisibilityTimeout = viper.GetInt("queue_timeout")
	o.QueueWaitTimeInSeconds = viper.GetInt("queue_wait")
	o.ReadTimeout = time.Duration(viper.GetInt("read_timeout")) * time.Second
	o.ShutdownWait = time.Duration(viper.GetInt("shutdown_wait")) * time.Second
	o.ValidAppsQueryPath = viper.GetString("valid_apps_query_path")
	o.SlackUrl = viper.GetString("slack_url")
	o.ValidAppsDeployPath = viper.GetString("valid_apps_deploy_path")
	o.WorkerPollInt = viper.GetInt("worker_poll_interval")
	o.WriteTimeout = time.Duration(viper.GetInt("write_timeout")) * time.Second
}

// String is an implentation of the Stringer interface so the structure is returned as a string
// to fmt.Print() etc.
func (o *Options) String() string {
	b, _ := json.Marshal(o)
	return string(b)
}
