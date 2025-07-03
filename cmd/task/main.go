package main

import (
	"cylonix/sase/cmd/statistics"
	"cylonix/sase/cmd/task/services"
	"cylonix/sase/pkg/logging"
	"flag"
	"log"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func setLogLevel(verbose bool, logger *logrus.Logger) {
	if verbose {
		logger.SetLevel(logrus.DebugLevel)
		return
	}
	logLevel := viper.GetString("log_level")
	if logLevel == "" {
		logger.SetLevel(logrus.WarnLevel)
	} else if level, err := logrus.ParseLevel(logLevel); err == nil {
		logger.SetLevel(level)
	}
}

func getTaskConfig() *services.TaskConfig {
	taskConfig := &services.TaskConfig{}
	if err := viper.UnmarshalKey("task_config", taskConfig); err != nil {
		log.Fatalf("Error unmarshal task config: %v\n", err)
	}
	return taskConfig
}

func main() {
	config := flag.String("config", "/etc/cylonix/config.yaml", "manager config")
	verbose := flag.Bool("verbose", false, "verbose")
	flag.Parse()

	viper.SetEnvPrefix("cylonix")
	viper.AutomaticEnv()
	viper.SetConfigFile(*config)

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %v\n", err)
	}

	taskConfig := getTaskConfig()
	logger := logging.DefaultLogger.WithField("service", "statistics")
	setLogLevel(*verbose, logger.Logger)

	prometheus := statistics.PrometheusServerInit()
	prometheus.Run()

	logger.Infoln("Creating new task table.")
	ts, err := services.NewTaskTable(logger, taskConfig)
	if err != nil {
		log.Fatalln("Failed to create new task table.")
	}
	ts.TaskList = append(ts.TaskList, services.NewPrometheusTaskInstance(ts, prometheus))
	ts.TaskList = append(ts.TaskList, services.NewCleanTask(ts))

	viper.OnConfigChange(func(e fsnotify.Event) {
		logger.Warnln("Task config changed.")
		setLogLevel(*verbose, logger.Logger)
		ts.Config = getTaskConfig()
	})
	viper.WatchConfig()

	logger.Infoln("Starting tasks.")
	ts.Run()
}
