package cmd

import (
	"fmt"
	"os"

	"github.com/composer22/k8ctl-server/server"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Used globally for all commands.
var (
	cfgFile string
	debug   bool
)

// RootCmd represents the base command when called without any subcommands.
var RootCmd = &cobra.Command{
	Use:   "k8ctl-server",
	Short: "Manage Kubernetes command for client",
	Long:  "Server for managing a subset of commands w/ Kubernetes clusters.",
}

// Execute adds all child commands to the root command sets flags appropriately.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

// Boot init.
func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is $HOME/.k8ctl-server.yaml)")
	RootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug")
}

// Err and die.
func er(msg interface{}) {
	fmt.Println("Error:", msg)
	os.Exit(1)
}

// initConfig reads in config file.
func initConfig() {
	viper.SetDefault("auth_path_prefix", server.DefaultAuthPathPrefix)
	viper.SetDefault("health_route", server.HttpRouteDefaultHealth)
	viper.SetDefault("host_name", server.DefaultHostname)
	viper.SetDefault("port", server.DefaultPort)
	viper.SetDefault("profiler_port", 0)
	viper.SetDefault("queue_send_delay", server.DefaultQueueSendDelay)
	viper.SetDefault("queue_timeout", server.DefaultQueueVisibilityTimeout)
	viper.SetDefault("queue_wait", server.DefaultQueueWaitTimeInSeconds)
	viper.SetDefault("read_timeout", server.DefaultReadTimeout)
	viper.SetDefault("shutdown_wait", server.DefaultShutdownWait)
	viper.SetDefault("worker_poll_interval", server.DefaultWorkerPollInt)
	viper.SetDefault("write_timeout", server.DefaultWriteTimeout)

	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			er(err)
		}
		viper.AddConfigPath(home)            // Adding home directory as first search path.
		viper.AddConfigPath(".")             // Adding current directory as second search path.
		viper.SetConfigName(".k8ctl-server") // name of config file (without extension).
	}
	viper.AutomaticEnv()
	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Cannot find configuration file.\n\nERR: %s\n", err.Error())
		os.Exit(0)
	}
}
