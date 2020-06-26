package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"

	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/composer22/k8ctl-server/logger"
	"github.com/gin-gonic/gin"
	"github.com/slack-go/slack"
)

// Server - wrapper around the API server.
type Server struct {
	done    chan bool          // A channel to signal to go routine workers to close down.
	gtmpl   *template.Template // Guide template for extended help (we precompile once).
	log     *logger.Logger     // Log instance for recording error and other messages.
	mu      sync.RWMutex       // For locking access to server attributes.
	opt     *Options           // Original options used to create the server.
	router  *gin.Engine        // Represents the http router within the srvr.
	running bool               // Is the server running?
	sess    *session.Session   // AWS session for the run.
	slack   *slackWorker       // Slack worker for handling RTM messaging.
	sqssvc  *sqs.SQS           // AWS Simple Queuing Service connection.
	srvr    *http.Server       // Customized HTTP server.
	ssmsvc  *ssm.SSM           // AWS Parameter Store connection.
	wg      sync.WaitGroup     // Synchronize shutdown pending jobs.
}

// NewServer is a factory function that returns a new client instance.
func NewServer(options *Options, logr *logger.Logger) (*Server, error) {
	if options.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	gin.DisableConsoleColor()
	// Prepare guide template for processing later in the route.
	t, err := template.New("guide").Parse(GuideTemplate)
	if err != nil {
		return nil, err
	}

	s := &Server{
		done:    make(chan bool),
		gtmpl:   t,
		log:     logr,
		opt:     options,
		router:  gin.New(),
		running: false,
	}

	// Extra middleware.
	s.router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.Referer(),
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	}))
	s.router.Use(gin.Recovery())
	s.router.Use(s.prepareResponseHeader) // Standard across all responses.
	s.router.Use(s.validateAccess)        // Check API token access.
	s.router.Use(s.getMetadata)           // Get the resource type, api version for the route.
	s.router.Use(s.validateHeader)        // Make sure API version and content type are AOK.

	if options.Debug {
		s.log.SetLogLevel(logger.Debug)
	}

	s.configRoutes(s.router)
	return s, nil
}

// Start spins up the server to accept incoming requests.
func (s *Server) Start() error {
	if s.isRunning() {
		return errors.New("Server already started.")
	}
	s.handleSignals()
	s.mu.Lock()

	// Connect to AWS, SQS, Param Store.
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.sqssvc = sqs.New(sess) // Simple Queing Service
	s.ssmsvc = ssm.New(sess) // Parameter Store

	// Optional slack worker for handling RTM messaging and prompting for the deploy.
	if s.opt.SlackAPITokenPath != "" {
		s.slack, err = NewSlackWorker(s)
		if err != nil {
			return err
		}
	}

	// Start the worker service which handles delete, deployments, rollbacks, restarts.
	d := NewWorker(s.done, s.log, s.opt, s.sqssvc, s.ssmsvc, &s.wg)
	go d.Run()

	// Optionally start the slack worker.
	if s.slack != nil {
		go s.slack.Run()
	}
	// Pprof http endpoint for the profiler.
	if s.opt.ProfPort > 0 {
		s.StartProfiler()
	}

	// Main server.
	s.srvr = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", s.opt.Hostname, s.opt.Port),
		Handler:      s.router,
		ReadTimeout:  s.opt.ReadTimeout,
		WriteTimeout: s.opt.WriteTimeout,
	}

	s.running = true
	s.mu.Unlock()

	defer s.Shutdown() // Close out worker etc.

	// Run API server and wait . . .
	if err = s.srvr.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Version prints the version of the server.
func Version() string {
	return fmt.Sprintf("%s version %s\n", applicationName, version)
}

// StartProfiler is called to enable dynamic profiling.
func (s *Server) StartProfiler() {
	s.log.Infof("Starting profiling on host %s port %d", s.opt.Hostname, s.opt.ProfPort)
	go func() {
		if err := http.ListenAndServe(fmt.Sprintf("%s:%d", s.opt.Hostname, s.opt.ProfPort), nil); err != nil {
			s.log.Errorf("Profile monitoring service: %s", err)
		}
	}()
}

// Shutdown waits for jobs to be complete and closes out all resources.
func (s *Server) Shutdown() {
	if !s.isRunning() {
		return
	}
	s.log.Infof("Begin server service stop.")
	s.mu.Lock()
	close(s.done) // Signal workers we are done.
	s.wg.Wait()   // Wait for them to finish.

	if s.slack != nil {
		s.slack.RunDone() // Tell all slack channels we are exiting.
	}
	s.running = false
	s.mu.Unlock()
	s.log.Infof("End server service stop.")
}

// handleSignals responds to operating system interrupts such as application kills.
func (s *Server) handleSignals() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-c // Wait for signals
		s.log.Infof("Server received signal: %v\n", sig)

		// Give server n seconds to shut itself down
		ctx, cancel := context.WithTimeout(context.Background(), s.opt.ShutdownWait)
		defer cancel()
		s.srvr.SetKeepAlivesEnabled(false)
		if err := s.srvr.Shutdown(ctx); err != nil {
			log.Fatal("Server forced to shutdown:", err.Error())
		}
	}()
}

// Configure incoming routes for all requests.
func (s *Server) configRoutes(r *gin.Engine) {
	// Helm related.
	r.GET(httpRouteReleases, s.releasesList)
	r.POST(httpRouteReleases, s.releasesDeploy)
	r.GET(httpRouteRelease, s.releaseStatus)
	r.DELETE(httpRouteRelease, s.releaseDelete)
	r.PUT(httpRouteReleaseRollback, s.releaseRollback)
	r.GET(httpRouteReleaseHistory, s.releaseHistory)

	// Kubectl related
	r.GET(httpRouteConfigmaps, s.handleList)
	r.GET(httpRouteConfigmap, s.handleDetails)
	r.GET(httpRouteCronjobs, s.handleList)
	r.GET(httpRouteCronjob, s.handleDetails)
	r.GET(httpRouteDeployments, s.handleList)
	r.GET(httpRouteDeployment, s.handleDetails)
	r.PATCH(httpRouteDeploymentRestart, s.deploymentRestart)
	r.GET(httpRouteIngresses, s.handleList)
	r.GET(httpRouteIngress, s.handleDetails)
	r.GET(httpRouteJobs, s.handleList)
	r.GET(httpRouteJob, s.handleDetails)
	r.GET(httpRoutePods, s.handleList)
	r.GET(httpRoutePod, s.handleDetails)
	r.GET(httpRouteServices, s.handleList)
	r.GET(httpRouteService, s.handleDetails)

	// Other
	r.GET(httpRouteGuide, s.guide) // extended dynamic help
	r.GET(s.opt.HealthRoute, s.healthCheck)
	r.POST(httpRouteSlackInteractive, s.slackInteractive)

}

/************************************/
/************ HANDLERS **************/
/************************************/

// Get a list of helm releases.
func (s *Server) releasesList(c *gin.Context) {
	var namespace, format, result string
	var err error
	if namespace, err = s.validateNamespace(c, c.Query(httpParamNamespace)); err != nil {
		return
	}
	if format, err = s.validateFormat(c); err != nil {
		return
	}

	// Get the list of releases.
	cmd := exec.Command("./scripts/helm-list.sh", namespace, format)
	if result, err = execCmd(cmd); err != nil {
		s.log.Errorf("helm-list.sh: %s %s", err.Error(), result)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": fmt.Sprintf("Unable to get release list."),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": result,
	})
}

// Deploy a new release.
func (s *Server) releasesDeploy(c *gin.Context) {
	var req DeployRequest
	var err error

	if err = c.ShouldBindJSON(&req); err != nil {
		s.log.Errorf("JSON Bind: %s", err.Error())
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "Invalid JSON payload. Cannot be read.",
		})
		return
	}

	// Validate name - approves apps only.
	name := req.Name
	resource := c.GetString("resource")
	if err = s.validateApp(c, resource, name, s.opt.ValidAppsDeployPath, true); err != nil {
		return
	}

	// Validate version tag. (Mandatory)
	if req.VersionTag == "" {
		s.log.Errorf("Version tag is mandatory.")
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "Version of application is mandatory for a deploy.",
		})
		return
	}

	// Validate namespace
	if _, err = s.validateNamespace(c, req.Namespace); err != nil {
		return
	}

	user := c.GetString("user")
	body, _ := json.Marshal(req)
	if err = s.queueJob(req.Name, user, JobTypeDeploy, string(body)); err != nil {
		s.log.Errorf("Queue: %s", err.Error())
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": fmt.Sprintf("Could not queue %s:%s to be deployed.", req.Name, req.VersionTag),
		})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"status":  "Accepted",
		"message": fmt.Sprintf("%s:%s was queued for deployment.", req.Name, req.VersionTag),
	})
}

// Get a release status.
func (s *Server) releaseStatus(c *gin.Context) {
	var format, result string
	var err error

	if format, err = s.validateFormat(c); err != nil {
		return
	}

	name := c.Param("name")

	// Get the status of a release.
	cmd := exec.Command("./scripts/helm-status.sh", name, format)
	if result, err = execCmd(cmd); err != nil {
		s.log.Errorf("helm-status.sh: %s %s", err.Error(), result)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": fmt.Sprintf("Unable to get status for release %s.", name),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": result,
	})
}

// Delete a release.
func (s *Server) releaseDelete(c *gin.Context) {
	// Validate Name - approved apps only
	name := c.Param("name")
	resource := c.GetString("resource")
	if err := s.validateApp(c, resource, name, s.opt.ValidAppsQueryPath, false); err != nil {
		return
	}

	user := c.GetString("user")
	if err := s.queueJob(name, user, JobTypeDelete, "{}"); err != nil {
		s.log.Errorf("Queue: %s", err.Error())
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": fmt.Sprintf("Could not queue release %s to be deleted.", name),
		})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"status":  "ok",
		"message": fmt.Sprintf("Release %s was queued to be deleted.", name),
	})
}

// Roll back a release.
func (s *Server) releaseRollback(c *gin.Context) {
	// Validate Name - approved apps only
	name := c.Param("name")
	resource := c.GetString("resource")
	if err := s.validateApp(c, resource, name, s.opt.ValidAppsQueryPath, false); err != nil {
		return
	}

	var req RollbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.log.Errorf("JSON Bind: %s", err.Error())
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "Invalid JSON payload. Cannot be read.",
		})
		return
	}

	// Cleanup revision to default
	if req.Revision == "" {
		req.Revision = "0" // previous
	}

	user := c.GetString("user")
	body, _ := json.Marshal(req)
	if err := s.queueJob(name, user, JobTypeRollback, string(body)); err != nil {
		s.log.Errorf("Queue: %s", err.Error())
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": fmt.Sprintf("Could not queue release %s to be rolled back to revision %s.", name, req.Revision),
		})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"status":  "ok",
		"message": fmt.Sprintf("Release %s was queued to be rollbacked to revision %s.", name, req.Revision),
	})
}

// Get deployment history of a release.
func (s *Server) releaseHistory(c *gin.Context) {
	var format, result string
	var err error
	if format, err = s.validateFormat(c); err != nil {
		return
	}

	name := c.Param("name")

	// Get the history of a release.
	cmd := exec.Command("./scripts/helm-history.sh", name, format)
	if result, err = execCmd(cmd); err != nil {
		s.log.Errorf("helm-history.sh: %s %s", err.Error(), result)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": fmt.Sprintf("Unable to get history for release %s.", name),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": result,
	})
}

// Restart a deployment in the cluster.
func (s *Server) deploymentRestart(c *gin.Context) {
	// Validate Name - approved apps only
	name := c.Param("name")
	resource := c.GetString("resource")
	if err := s.validateApp(c, resource, name, s.opt.ValidAppsQueryPath, false); err != nil {
		return
	}

	var req RestartRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.log.Errorf("JSON Bind: %s", err.Error())
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": "Invalid JSON payload. Cannot be read.",
		})
		return
	}

	user := c.GetString("user")
	body, _ := json.Marshal(req)
	if err := s.queueJob(name, user, JobTypeRestart, string(body)); err != nil {
		s.log.Errorf("Queue: %s", err.Error())
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": fmt.Sprintf("Could not queue deployment %s to be restarted.", name),
		})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"status":  "ok",
		"message": fmt.Sprintf("Deployment %s was queued to be restarted", name),
	})
}

// Generic routine to return K8 get list for a resource type.
func (s *Server) handleList(c *gin.Context) {
	var format, namespace, result string
	var err error
	if namespace, err = s.validateNamespace(c, c.Query(httpParamNamespace)); err != nil {
		return
	}
	if format, err = s.validateFormat(c); err != nil {
		return
	}
	resource := c.GetString("resource")

	// Get a list of resources.
	cmd := exec.Command("./scripts/k8-get.sh", resource, namespace, format)
	if result, err = execCmd(cmd); err != nil {
		s.log.Errorf("k8-get.sh: %s %s", err.Error(), result)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": fmt.Sprintf("Could not return a list of %s.", resource),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": result,
	})
}

// Generic routine to return K8 describe information on a resource.
func (s *Server) handleDetails(c *gin.Context) {
	var namespace, result string
	var err error
	if namespace, err = s.validateNamespace(c, c.Query(httpParamNamespace)); err != nil {
		return
	}
	name := c.Param("name")
	resource := c.GetString("resource")

	// Describe details of a resource.
	cmd := exec.Command("./scripts/k8-describe.sh", resource, name, namespace)
	if result, err = execCmd(cmd); err != nil {
		s.log.Errorf("k8-describe.sh: %s %s", err.Error(), result)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": fmt.Sprintf("Could not describe %s %s.", resource, name),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": result,
	})
}

// Structure for guide data as a source to rendering a template.
type GuideData struct {
	ValidAppsQuery  *[]string `json:"validAppsQuery"`  // List of valid apps for servicing
	ValidAppsDeploy *[]string `json:"validAppsDeploy"` // List of valid apps for deploy
	Namespaces      *[]string `json:"namespaces"`      //  List of valid namespaces for servicing

}

// Print out extended help.
func (s *Server) guide(c *gin.Context) {
	var validAppsQuery, validAppsDeploy []string
	var err error
	// Get latest app list from parameter store.
	if validAppsQuery, err = s.getValidApps(s.opt.ValidAppsQueryPath); err != nil {
		s.log.Errorf("Apps: %s", err.Error())
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Internal error retrieving valid query apps.",
		})
		return
	}
	// Get latest app list from parameter store.
	if validAppsDeploy, err = s.getValidApps(s.opt.ValidAppsDeployPath); err != nil {
		s.log.Errorf("Apps: %s", err.Error())
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Internal error retrieving valid deploy apps.",
		})
		return
	}
	sort.Strings(validAppsQuery)
	sort.Strings(validAppsDeploy)

	// Structure data for template.
	data := &GuideData{
		ValidAppsQuery:  &validAppsQuery,
		ValidAppsDeploy: &validAppsDeploy,
		Namespaces:      &s.opt.Namespaces,
	}

	// Render
	var b bytes.Buffer
	if err := s.gtmpl.Execute(&b, data); err != nil {
		s.log.Errorf("Template render: %s", err.Error())
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Internal error rendering template.",
		})
		return
	}

	// Return the guide
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": b.String(),
	})
}

// Server health check.
func (s *Server) healthCheck(c *gin.Context) {
	// TODO Add additional validations regarding AWS services.
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": "healthy",
	})
}

/************************************/
/********** SLACK HANDLING **********/
/************************************/

// Handles post requests from Slack for deploy processing.
func (s *Server) slackInteractive(c *gin.Context) {

	// No slack object? Then this route is disabled.
	if s.slack == nil {
		s.log.Errorf("Slack service is disabled in this server")
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"status":  "error",
			"message": "Route not found.",
		})
		return
	}

	// Validate the request signature

	// Retrieve signing secret
	t, err := s.ssmsvc.GetParameter(
		&ssm.GetParameterInput{
			Name:           aws.String(s.opt.SlackSigningSecretPath),
			WithDecryption: aws.Bool(true),
		})
	if err != nil {
		s.log.Errorf("Unable to retrieve signing secret. Error: %s", err.Error())
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Unable to verify signature.",
		})
		return
	}
	signingSecret := aws.StringValue(t.Parameter.Value)

	// Create secrets verifier
	sv, err := slack.NewSecretsVerifier(c.Request.Header, signingSecret)
	if err != nil {
		s.log.Errorf("Failed to verify signing secret: %s", err.Error())
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"status":  "error",
			"message": "Failed to verify signing secret.",
		})
		return
	}

	// Read body of request
	defer c.Request.Body.Close()
	b, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		s.log.Errorf("Could not read body of request.")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Unable to read body.",
		})
		return
	}

	// Verify secrets.
	sv.Write(b) // Move body to verifier
	if err := sv.Ensure(); err != nil {
		s.log.Errorf("Failed to verify signing secret: %s", err.Error())
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"status":  "error",
			"message": "Failed to verify signing secret.",
		})
		return
	}

	// Unescape the body content.
	jsonStr, err := url.QueryUnescape(string(b)[8:])
	if err != nil {
		s.log.Errorf("Could not unescape body of request.")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Unable to unescape body.",
		})
		return
	}

	// Unmarshal into struct.
	var callback slack.InteractionCallback
	err = json.Unmarshal([]byte(jsonStr), &callback)
	if err != nil {
		s.log.Errorf("Could not unmarshal body of request.")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Unable to unmarshal body.",
		})
		return
	}

	// Validate the user is in the same team as the bot.
	botinfo, err := s.slack.api.AuthTest()
	if err != nil {
		s.log.Errorf("Could not retrieve bot information.")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Unable to retrieve account info.",
		})
		return
	}
	user, err := s.slack.api.GetUserInfo(callback.User.ID)
	if user.TeamID != botinfo.TeamID {
		s.log.Errorf("User is not on same team as bot.")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"status":  "error",
			"message": "User is not on team.",
		})
		return
	}
	// Validate the user can deploy.
	if err := s.slack.validateUserAuth(callback.User.ID); err != nil {
		s.log.Errorf("User is not authorized to deploy.")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"status":  "error",
			"message": "User is not authorized to deploy.",
		})
		return
	}

	// Now, handle the event.
	if err := s.slackHandlerEvent(c, &callback, jsonStr); err != nil {
		s.log.Errorf("slackHandlerEvent: %s", err.Error())
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"message": "Internal error processing event.",
		})
	}
	return
}

// slackHandlerEvent - main handler for the events from Slack.
func (s *Server) slackHandlerEvent(c *gin.Context, message *slack.InteractionCallback, body string) error {
	switch message.Type {
	// Button or select option pressed?
	case slack.InteractionTypeBlockActions:
		if err := s.blockActionEvent(message); err != nil {
			return err
		}
		// Process the message.
		result := "OK"
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"message": result,
		})

	// Final view submission
	case slack.InteractionTypeViewSubmission:
		// Harvest and validate.
		var namespace, repo, tag, memo string
		if n, ok := message.View.State.Values["namespaceSelected"]["namespaceSelected"]; ok {
			namespace = n.SelectedOption.Value
		}
		if r, ok := message.View.State.Values["repoSelected"]["repoSelected"]; ok {
			repo = r.SelectedOption.Value
		}
		if t, ok := message.View.State.Values["imageTag"]["imageTag"]; ok {
			tag = t.Value
		}
		if m, ok := message.View.State.Values["memo"]["memo"]; ok {
			memo = m.Value
		}
		if err := s.validateDeployModal(c, tag); err != nil {
			s.log.Errorf("validateDeployModal: %s", err.Error())
			return nil // we handled this event w/ special message to modal.
		}

		// Send deploy job to processing queue.
		req := &DeployRequest{
			Memo:       memo,
			Name:       repo,
			Namespace:  namespace,
			VersionTag: tag,
		}
		body, _ := json.Marshal(req)
		if err := s.queueJob(req.Name, message.User.Name, JobTypeDeploy, string(body)); err != nil {
			return errors.New(fmt.Sprintf("Queue: %s", err.Error()))
		}

		c.JSON(http.StatusOK, gin.H{
			"response_action": "clear",
		})

	}
	return nil
}

// blockActionEvent - handles any block actions.
func (s *Server) blockActionEvent(message *slack.InteractionCallback) error {
	for _, a := range message.ActionCallback.BlockActions {
		switch a.ActionID {
		// Launch the modal form - get the key deploy data for submission.
		case "start_01":
			modalView, err := s.slack.deployModal()
			if err != nil {
				return err
			}
			_, err = s.slack.api.OpenView(message.TriggerID, modalView)
			if err != nil {
				return err
			}
			// Delete original launcher message.
			_, _, err = s.slack.api.DeleteMessage(message.Channel.ID, message.Message.Timestamp)
			if err != nil {
				return err
			}
		case "cancel_01":
			// Delete original launcher message.
			if _, _, err := s.slack.api.DeleteMessage(message.Channel.ID, message.Message.Timestamp); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateDeployModal - validates the modal dialog data returned for processing.
// Returns error message if data is invalid.

type SlackDeployErrResponse struct {
	ResponseAction string `json:"response_action"`
	Errors         struct {
		NamespaceSelected string `json:"namespaceSelected,omitempty"`
		RepoSelected      string `json:"repoSelected,omitempty"`
		ImageTag          string `json:"imageTag,omitempty"`
	} `json:"errors"`
}

func (s *Server) validateDeployModal(c *gin.Context, tag string) error {
	if strings.HasPrefix(tag, s.opt.ImageTagPrefix) {
		return nil
	}
	errMsg := &SlackDeployErrResponse{ResponseAction: "errors"}
	errMsg.Errors.ImageTag = fmt.Sprintf("Image tag must begin with '%s'.", s.opt.ImageTagPrefix)
	c.JSON(http.StatusOK, errMsg)
	return errors.New(fmt.Sprintf("Invalid image tag: %s", tag))
}

/************************************/
/********** MIDDLEWARE **************/
/************************************/

// Sets up common response header for the return trip.
func (s *Server) prepareResponseHeader(c *gin.Context) {
	requestID := c.GetHeader("X-Request-ID")
	if requestID == "" {
		requestID = createV4UUID()
	}
	c.Header("Content-Type", "application/json")
	c.Header("Date", time.Now().UTC().Format(time.RFC1123Z))
	c.Header("X-Request-ID", requestID)
	c.Next()
}

// Authenticate access to the server.
func (s *Server) validateAccess(c *gin.Context) {
	// Healthcheck and Slack can be ignored. Slack will process with the message.
	if (c.FullPath() == s.opt.HealthRoute) || (c.FullPath() == httpRouteSlackInteractive) {
		c.Next()
		return
	}
	errFound := false
	bearer := c.GetHeader("Authorization")
	bearer = strings.Replace(bearer, "Bearer ", "", 1) // Remove constant
	// Token is in two parts: access id (auth[0]) + secret token (auth[1])
	auth := strings.Split(bearer, httpAuthDelimeter)
	if len(auth) != 2 {
		errFound = true
	} else {
		// Validate /<prefix path>/:accessid/token
		t, err := s.ssmsvc.GetParameter(
			&ssm.GetParameterInput{
				Name:           aws.String(fmt.Sprintf("%s/%s/%s", s.opt.AuthPathPrefix, auth[0], ssmTokenSubpath)),
				WithDecryption: aws.Bool(true),
			})
		if (err != nil) || (aws.StringValue(t.Parameter.Value) != auth[1]) {
			errFound = true
		}
	}
	// Any auth error kills the request.
	if errFound == true {
		s.log.Errorf("Authorization: %s", bearer)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"status":  "error",
			"message": "Invalid authorization.",
		})
		return
	}

	// Let's try and get the user name and add it as an attribute to the request.
	usr, err := s.ssmsvc.GetParameter(
		&ssm.GetParameterInput{
			Name:           aws.String(fmt.Sprintf("%s/%s/%s", s.opt.AuthPathPrefix, auth[0], ssmUserSubpath)),
			WithDecryption: aws.Bool(false),
		})

	if err != nil {
		c.Set("user", "unknown")
	} else {
		c.Set("user", aws.StringValue(usr.Parameter.Value))

	}
	c.Next()
}

// Check the route and set metadata for later processing (transformations)
func (s *Server) getMetadata(c *gin.Context) {
	var resource, apiResource, apiVersion string
	route := c.FullPath()

	switch route {
	case httpRouteReleases:
		resource, apiResource, apiVersion = "releases", "releases", httpRouteReleasesVersion
	case httpRouteRelease, httpRouteReleaseRollback, httpRouteReleaseHistory:
		resource, apiResource, apiVersion = "release", "releases", httpRouteReleasesVersion
	case httpRouteConfigmaps:
		resource, apiResource, apiVersion = "configmaps", "configmaps", httpRouteConfigmapsVersion
	case httpRouteConfigmap:
		resource, apiResource, apiVersion = "configmap", "configmaps", httpRouteConfigmapsVersion
	case httpRouteCronjobs:
		resource, apiResource, apiVersion = "cronjobs", "cronjobs", httpRouteCronjobsVersion
	case httpRouteCronjob:
		resource, apiResource, apiVersion = "cronjob", "cronjobs", httpRouteCronjobsVersion
	case httpRouteDeployments:
		resource, apiResource, apiVersion = "deployments", "deployments", httpRouteDeploymentsVersion
	case httpRouteDeployment, httpRouteDeploymentRestart:
		resource, apiResource, apiVersion = "deployment", "deployments", httpRouteDeploymentsVersion
	case httpRouteIngresses:
		resource, apiResource, apiVersion = "ingresses", "ingresses", httpRouteIngressesVersion
	case httpRouteIngress:
		resource, apiResource, apiVersion = "ingress", "ingresses", httpRouteIngressesVersion
	case httpRouteJobs:
		resource, apiResource, apiVersion = "jobs", "jobs", httpRouteJobsVersion
	case httpRouteJob:
		resource, apiResource, apiVersion = "job", "jobs", httpRouteJobsVersion
	case httpRoutePods:
		resource, apiResource, apiVersion = "pods", "pods", httpRoutePodsVersion
	case httpRoutePod:
		resource, apiResource, apiVersion = "pod", "pods", httpRoutePodsVersion
	case httpRouteServices:
		resource, apiResource, apiVersion = "services", "services", httpRouteServicesVersion
	case httpRouteService:
		resource, apiResource, apiVersion = "service", "services", httpRouteServicesVersion
	case httpRouteGuide:
		resource, apiResource, apiVersion = "guide", "guide", httpRouteGuideVersion
	case s.opt.HealthRoute:
		resource, apiResource, apiVersion = "health", "health", httpRouteHealthVersion
	case httpRouteSlackInteractive:
		resource, apiResource, apiVersion = "slack", "slack", httpRouteSlackVersion
	default:
		s.log.Errorf("Invalid Path: %s", c.Request.URL.Path)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": fmt.Sprintf("Path %s is invalid.", c.Request.URL.Path),
		})
		return
	}

	// Set the default values for this request for later processing.
	c.Set("resource", resource)
	a := fmt.Sprintf(apiVersionTmpl, applicationName, apiResource, apiVersion)
	c.Set("currentAPIVersion", a)
	c.Next()
}

// Authenticate mandatory header values.
func (s *Server) validateHeader(c *gin.Context) {
	// Healthcheck and Slack can be ignored. Slack will process with the message.
	if (c.FullPath() == s.opt.HealthRoute) || (c.FullPath() == httpRouteSlackInteractive) {
		c.Next()
		return
	}
	currentAPIVersion := c.GetString("currentAPIVersion")
	apiVersion := c.GetHeader("Accept")
	if apiVersion != currentAPIVersion {
		s.log.Errorf("Api Version: %s", apiVersion)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": fmt.Sprintf("Api version %s is invalid.", apiVersion),
		})
		return
	}

	// Validate Content Type
	contentType := c.ContentType()
	if contentType != httpContentType {
		s.log.Errorf("Content-Type: %s", contentType)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"message": fmt.Sprintf("Content type %s is invalid.", contentType),
		})
		return
	}
	c.Next()
}

/************************************/
/********** SUPPORTING **************/
/************************************/
// Gets a slice of valid applications from parameter store.
func (s *Server) getValidApps(path string) ([]string, error) {
	// Get the StringList of valid apps from parameter store.
	var err error
	var output *ssm.GetParameterOutput
	if output, err = s.ssmsvc.GetParameter(
		&ssm.GetParameterInput{
			Name:           aws.String(path),
			WithDecryption: aws.Bool(false),
		}); err != nil {
		return nil, errors.New("Could not retrieve valid apps.")
	}

	validApps := strings.Split(aws.StringValue(output.Parameter.Value), ",")
	return validApps, nil
}

// Validates that the namespace param is serviced by this server.
func (s *Server) validateNamespace(c *gin.Context, namespace string) (string, error) {
	for _, n := range s.opt.Namespaces {
		if n == namespace {
			return namespace, nil // Found. We are good.
		}
	}
	s.log.Errorf("Namespace: %s", namespace)
	c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
		"status":  "error",
		"message": fmt.Sprintf("Invalid namespace: %s", namespace),
	})
	return namespace, errors.New(fmt.Sprintf("Invalid namespace: %s", namespace))

}

// Validate the output format.
func (s *Server) validateFormat(c *gin.Context) (string, error) {
	format := c.Query(httpParamFormat)
	switch format {
	case "", "json", "yaml":
		return format, nil
	}
	s.log.Errorf("Invalid format: %s", format)
	c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
		"status":  "error",
		"message": fmt.Sprintf("Invalid format: %s", format),
	})
	return format, errors.New(fmt.Sprintf("Invalid format: %s", format))
}

// Validate that the name of the app, release or deployment contains a valid
// application name.
func (s *Server) validateApp(c *gin.Context, resource string, name string, path string, exactMatch bool) error {
	// Get the StringList of valid apps from parameter store.
	var validApps []string
	var err error
	if validApps, err = s.getValidApps(path); err != nil {
		return err
	}
	for _, a := range validApps {
		if exactMatch == true {
			if name == a {
				return nil // valid
			}
		} else {
			if strings.Contains(name, a) {
				return nil // valid
			}
		}
	}
	s.log.Errorf("Validate Apps: %s/%s", resource, name)
	c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
		"status":  "error",
		"message": fmt.Sprintf("Invalid  %s: %s", resource, name),
	})
	return errors.New(fmt.Sprintf("Invalid  %s: %s", resource, name))
}

// executeCommand executes a shell command and returns the result or an error
func (s *Server) executeCommand(cmd *exec.Cmd) (string, error) {
	var result string
	var err error
	if result, err = execCmd(cmd); err != nil {
		return result, err
	}
	return result, nil
}

// queueJob places a request on the SQS queue for later processing.
// An alternative to rolling this bearcode might be to leverage:
// https://github.com/RichardKnop/machinery
// We add attributes to the message as metadata for later processing.
func (s *Server) queueJob(name string, user string, jobType int, payload string) error {
	sendParams := &sqs.SendMessageInput{
		MessageDeduplicationId: aws.String(createV4UUID()),
		MessageGroupId:         aws.String(applicationName),
		MessageAttributes: map[string]*sqs.MessageAttributeValue{
			// delete, deploy, restart, rollback
			"JobType": &sqs.MessageAttributeValue{
				DataType:    aws.String("Number"),
				StringValue: aws.String(strconv.Itoa(jobType)),
			},
			// This is the name of the release or deployment.
			"Name": &sqs.MessageAttributeValue{
				DataType:    aws.String("String"),
				StringValue: aws.String(name),
			},
			// This is the username of the authorized user.
			"User": &sqs.MessageAttributeValue{
				DataType:    aws.String("String"),
				StringValue: aws.String(user),
			},
		},
		MessageBody: aws.String(payload), // json data from original request.
		QueueUrl:    aws.String(s.opt.QueueUrl),
	}
	_, err := s.sqssvc.SendMessage(sendParams)
	return err
}

// isRunning returns a boolean the server is running or not.
func (s *Server) isRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}
