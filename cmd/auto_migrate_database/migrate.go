// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"cylonix/sase/daemon/db"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/postgres"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func drop(tables []string, dryRun bool) {
	pg, err := postgres.Connect()
	if err != nil {
		fatal(fmt.Sprintf("Failed to connect pg: %v", err), dryRun)
	}
	for _, table := range tables {
		if table == "" {
			continue
		}
		if dryRun {
			fmt.Printf("Dry-run: dropping table %v\n", table)
			continue
		}
		if err = pg.Migrator().DropTable(table); err != nil {
			log.Fatalf("Failed to drop table : %s %v", table, err)
		}
		log.Printf("Table %v is dropped.", table)
	}
}

func fatal(msg string, dryRun bool) {
	if !dryRun {
		log.Fatal(msg)
	} else {
		fmt.Println("Dry-run:", msg)
		os.Exit(1)
	}
}

func main() {
	configFile := flag.String("config", "/etc/cylonix/config.yaml", "manager config yaml file")
	dropTables := flag.String("drop", "", "a list of tables to drop e.g. 'users labels machines'")
	dropAll := flag.Bool("drop-all", false, "drop all tables before migration")
	dryRun := flag.Bool("dry-run", false, "show steps but do not execute database operation")
	tables := flag.String("tables", "", "a list of tables to migrate e.g. 'TenantConfig")
	namespaces := flag.String("namespaces", "", "a list of namespaces to migrate (only works with tables option)")
	verbose := flag.Bool("verbose", false, "verbose")

	flag.Parse()
	setting := utils.ConfigCheckSetting{
		Postgres: true,
	}
	if *verbose {
		db.SetLogLevel(logrus.DebugLevel)
	} else {
		db.SetLogLevel(logrus.ErrorLevel)
	}

	viper.SetEnvPrefix("cylonix")
	viper.AutomaticEnv()
	viper.SetConfigFile(*configFile)
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %v\n", err)
	}

	if _, err := utils.InitCfgFromViper(viper.GetViper(), setting); err != nil {
		fatal(fmt.Sprintf("Init config failed: %v", err), *dryRun)
	}
	dsn, dbName, err := utils.PostgresConfig()
	if err != nil {
		fatal(fmt.Sprintf("Failed to get postgres config: %v", err), *dryRun)
	}
	if err = postgres.Init(dsn, dbName, db.Tables()); err != nil {
		fatal(fmt.Sprintf("Failed to initialize postgres: %v", err), *dryRun)
	}
	if *dropTables != "" {
		drop(strings.Split(*dropTables, " "), *dryRun)
	}
	if *dryRun {
		fmt.Println("Dry-run: skip migrating tables.")
		return
	}
	if *tables != "" {
		if err = db.InitPGModelsByNames(*dropAll, strings.Split(*tables, " "), strings.Split(*namespaces, " ")); err != nil {
			log.Fatalf("Failed to migrate tables: %v", err)
		}
		log.Printf("DONE migrating %v", *tables)
		return
	}
	if err = db.InitPGModels(*dropAll); err != nil {
		log.Fatalf("Failed to init default models: %v", err)
	}
}
