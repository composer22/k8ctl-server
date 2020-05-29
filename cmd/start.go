package cmd

import (
	"errors"
	"fmt"

	"github.com/composer22/k8ctl-server/logger"
	"github.com/composer22/k8ctl-server/server"
	"github.com/spf13/cobra"
)

var (
	log      *logger.Logger
	startCmd = &cobra.Command{
		Use:   "start",
		Short: "Start the server",
		Long:  "Starts the server to accept incoming requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			return startServer()
		},
		Example: `k8ctl-server start`,
	}
)

// Boot init.
func init() {
	log = logger.New(logger.UseDefault, false)
	RootCmd.AddCommand(startCmd)
}

// Read in the options from the config file and start the server.
func startServer() error {
	opt := server.NewOptions(debug)
	srvr, err := server.NewServer(opt, log)
	if err != nil {
		log.Errorf("Server create Error: %s", err.Error())
		return errors.New(fmt.Sprintf("Server create: %s", err.Error()))
	}
	if err := srvr.Start(); err != nil {
		log.Errorf("Server run Error: %s", err.Error())
		return errors.New(fmt.Sprintf("Server run: %s", err.Error()))
	}
	return nil
}
