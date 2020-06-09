package server

const (
	applicationName = "k8ctl-server" // Application name.
	version         = "1.0.6"        // Application version.

	// Config file defaults (yml)
	DefaultAuthPathPrefix         = "/k8ctl-server/auth"
	DefaultHostname               = "localhost"
	DefaultPort                   = 8080
	DefaultQueueVisibilityTimeout = 20
	DefaultQueueWaitTimeInSeconds = 10
	DefaultReadTimeout            = 10
	DefaultShutdownWait           = 20
	DefaultWorkerPollInt          = 10
	DefaultWriteTimeout           = 10

	ssmTokenSubpath = "token"
	ssmUserSubpath  = "name"
	apiVersionTmpl  = "application/vnd.%s.%s-%s+json"

	httpAuthDelimeter  = "/"                // ex: accessid + '/' + secret
	httpContentType    = "application/json" // Always
	httpParamFormat    = "f"                // Query param f = json, yaml (optional)
	httpParamNamespace = "n"                // Query param n = ex: dev,dev2,qa. Range set in config file. (mandatory on gets)

	// ROUTES

	// Helm related
	httpRouteReleases        = "/releases"                // List, deploy releases.(?e=environment; POST)
	httpRouteRelease         = "/releases/:name"          // Get, or Delete a release. (GET=status; DELETE=delete)
	httpRouteReleaseRollback = "/releases/:name/rollback" // Rollback a release. (PUT=rollback)
	httpRouteReleaseHistory  = "/releases/:name/history"  // Display the history of a release. (?e=environment)

	// Kube related
	httpRouteConfigmaps        = "/configmaps"                // Display a list of configmaps.
	httpRouteConfigmap         = "/configmaps/:name"          // Display details of a configmap.
	httpRouteCronjobs          = "/cronjobs"                  // Display a list of cronjobs.
	httpRouteCronjob           = "/cronjobs/:name"            // Display details of a cronjob.
	httpRouteDeployments       = "/deployments"               // Display a list of deployments.
	httpRouteDeployment        = "/deployments/:name"         // Display details of a deployment.
	httpRouteDeploymentRestart = "/deployments/:name/restart" // Restart a deployment and its pods (PATCH)
	httpRouteIngresses         = "/ingresses"                 // Display a list of ingresses.
	httpRouteIngress           = "/ingresses/:name"           // Display details of an ingress.
	httpRouteJobs              = "/jobs"                      // Display a list of jobs.
	httpRouteJob               = "/jobs/:name"                // Display details of a jobs.
	httpRoutePods              = "/pods"                      // Display a list of running pods.
	httpRoutePod               = "/pods/:name"                // Display details of a running pod.
	httpRouteSecrets           = "/secrets"                   // Display a list of secrets.
	httpRouteSecret            = "/secrets/:name"             // Display details of a secret.
	httpRouteServices          = "/services"                  // Display a list of running services.
	httpRouteService           = "/services/:name"            // Display details of a running service.

	// Other
	httpRouteGuide         = "/guide"  // Get information on how to use this application from the server.
	HttpRouteDefaultHealth = "/health" // Healthcheck. This is customizable so to obuscate the path. No header or auth is needed.

	// API Versions
	httpRouteReleasesVersion    = "v1.0.0"
	httpRouteConfigmapsVersion  = "v1.0.0"
	httpRouteCronjobsVersion    = "v1.0.0"
	httpRouteDeploymentsVersion = "v1.0.0"
	httpRouteIngressesVersion   = "v1.0.0"
	httpRouteJobsVersion        = "v1.0.0"
	httpRoutePodsVersion        = "v1.0.0"
	httpRouteSecretsVersion     = "v1.0.0"
	httpRouteServicesVersion    = "v1.0.0"
	httpRouteGuideVersion       = "v1.0.0"
	httpRouteHealthVersion      = "v1.0.0"

	// Methods.
	httpDelete = "DELETE"
	httpGet    = "GET"
	httpHead   = "HEAD"
	httpPatch  = "PATCH"
	httpPost   = "POST"
	httpPut    = "PUT"
	httpTrace  = "TRACE"

	// Misc
	JobTypeDelete   = 1 // iota didnt work as an int
	JobTypeDeploy   = 2
	JobTypeRestart  = 3
	JobTypeRollback = 4

	GuideTemplate = `
This CLI tool provides a subset of commands to interact with a server in a
kubernetes cluster to control helm releases and kubernetes entities.

Use  the "releases" commands to control and view helm releases in a cluster.
Helm features:
* delete
* deploy
* history
* list
* rollback
* status

Use the other commands to list and view details on entities already in k8.
Such as:
* configmaps
* cronjobs
* deployments (includes a restart command)
* ingresses
* jobs
* pods
* services

Only the following namespaces are valid:

Available Namespaces:
{{range .Namespaces}}{{"* "}}{{.}}{{"\n"}}{{end}}

A "releases" deploy command must match one of these repo names:
{{range .ValidAppsDeploy}}{{"* "}}{{.}}{{"\n"}}{{end}}

A "releases" delete, or rollback command, or a "deployments" restart command requires one of these names to be a substring of the name:
{{range .ValidAppsQuery}}{{"* "}}{{.}}{{"\n"}}{{end}}

Known Issues:
Describing details of an ingress may not work due to cluster incompatibility
with this tool. This might correct itself when the cluster is upgraded in the
future.

`
)
