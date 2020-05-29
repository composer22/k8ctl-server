package cmd

import (
	"fmt"

	"github.com/composer22/k8ctl-server/server"
	"github.com/spf13/cobra"
)

// versionCmd returns the version of the application.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Version of the application",
	Long:  "Returns the version of the application",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("%s\n", server.Version())
		return nil
	},
	Example: `k8ctl-server version`,
}

// Boot init.
func init() {
	RootCmd.AddCommand(versionCmd)
}
