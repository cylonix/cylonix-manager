/*
Copyright © 2025 EZBLOCK INC. & AUTHORS

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"context"
	"cylonix/sase/daemon"
	"cylonix/sase/daemon/db"
	"cylonix/sase/pkg/logging"
	"cylonix/sase/pkg/logging/logfields"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/etcd"
	"github.com/cylonix/utils/fabric"
	"github.com/cylonix/utils/postgres"
	"github.com/cylonix/utils/redis"

	gviper "github.com/spf13/viper"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "main")
	viper = gviper.New()
	cfgFile string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cylonix-manager",
	Short: "connection between network execution units and the end users",
	Long: `Cylonix manager is program working at control plan. It coordinates
with Firewall units, VPN access points and SD-WAN services to work for
the end user. It is a multi-tenant program. Every user locates in a specific
namespace. The namespace is consistent with VPN, Firewall and SD-WAN services.`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		if viper == nil {
			panic("nil viper setting")
		}

		daemon, err := daemon.NewDaemon(ctx, cmd, viper)
		if err != nil {
			log.Fatalf("Failed to create daemon: %v", err)
		}
		endpoints, err := utils.ETCDEndpoints()
		if err != nil {
			log.Fatalf("Failed to get etcd endpoints: %v", err)
		}
		if err = etcd.Init(utils.ETCDPrefix(), endpoints, daemon.Logger()); err != nil {
			log.Fatalf("Failed to init etcd: %v", err)
		}
		url, prefix, err := utils.RedisConfig()
		if err != nil {
			log.Fatalf("Failed to get redis config: %v", err)
		}
		if err = redis.Init(url, "", prefix); err != nil {
			log.Fatalf("Failed to init redis: %v", err)
		}
		dsn, dbName, err := utils.PostgresConfig()
		if err != nil {
			log.Fatalf("Failed to get postgres config: %v", err)
		}
		if err = postgres.Init(dsn, dbName, db.Tables()); err != nil {
			log.Fatalf("Failed to initialize postgres: %v", err)
		}

		fabric.RegisterResource(fabric.DatabaseEtcdType, fabric.OnlyOneService, daemon, log)
		fabric.Fire(fabric.DatabaseEtcdType, fabric.OnlyOneService, fabric.ActionOnline, log)

		log.Errorln("Start running daemon server....")
		if err := daemon.Run(); err != nil {
			log.Fatalf("Failed to run daemon: %v", err)
		}
		log.Errorln("Daemon server stopped running.")
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "/etc/cylonix/config.yaml", "start up config file")
	rootCmd.PersistentFlags().String("log-level", "info", "log level")

	viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	viper.BindPFlag("log-level", rootCmd.PersistentFlags().Lookup("log-level"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	log.Printf("Config file is set to %v", cfgFile)
	viper.SetConfigFile(cfgFile)

	viper.AutomaticEnv()
	log.Println("Using config file:", viper.ConfigFileUsed())

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Failed to read in config: %v", err)
	}
	viper.WatchConfig()
}
