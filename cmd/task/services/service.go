package services

import (
	"cylonix/sase/cmd/clients"
	"cylonix/sase/daemon/db"
	"cylonix/sase/pkg/logging/logfields"
	"encoding/json"
	"time"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/etcd"
	"github.com/cylonix/utils/postgres"
	"github.com/cylonix/utils/redis"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	wgConnConfigPrefix = "/cylonix/wg/instance/conn_config"
	defaultInterval    = 5 // seconds
)

type TaskItem interface {
	// Interval returns the task firing internal in seconds.
	Interval() int

	// Name returns the task name
	Name() string

	// Task runs the task. Full scan indicates if we should update all the
	// devices or only update those that have updates.
	Task(fullScan bool)
}

type TaskTable struct {
	Config   *TaskConfig
	TaskList []TaskItem
	Logger   *logrus.Entry
	stopCh   chan struct{}
}
type TaskConfig struct {
	WgConfig           []*clients.WgConfig `json:"wg_config"`
	Namespaces         []string            `json:"namespaces"`
	Interval           int                 `json:"interval"`
}

func NewTaskTable(logger *logrus.Entry, taskConfig *TaskConfig) (*TaskTable, error) {
	if taskConfig.Interval == 0 {
		taskConfig.Interval = 60
	}
	t := &TaskTable{
		Config:   taskConfig,
		TaskList: []TaskItem{},
		stopCh:   make(chan struct{}),
		Logger:   logger.WithField(logfields.LogSubsys, "task-service"),
	}
	if err := t.init(); err != nil {
		t.Logger.WithError(err).Errorln("Failed to initialize task table.")
		return nil, err
	}
	return t, nil
}
func (t *TaskTable) init() error {
	logger := t.Logger.WithFields(logrus.Fields{
		"config-file": viper.ConfigFileUsed(),
	})
	logger.Debugln("Checking config...")
	setting := utils.ConfigCheckSetting{
		Supervisor: true,
		Redis:      true,
		ETCD:       true,
		Prometheus: true,
		Postgres:   true,
	}
	if _, err := utils.InitCfgFromViper(viper.GetViper(), setting); err != nil {
		logger.WithError(err).Errorln("Failed to initialize manager config.")
		return err
	}
	redisURL, redisPrefix, err := utils.RedisConfig()
	if err != nil {
		logger.WithError(err).Errorln("Failed to get redis config.")
		return err
	}
	if err = redis.Init(redisURL, "", redisPrefix); err != nil {
		logger.WithError(err).Errorln("Failed to initialize redis.")
		return err
	}
	dsn, dbName, err := utils.PostgresConfig()
	if err != nil {
		logger.WithError(err).Errorln("Failed to get postgres config.")
		return err
	}
	if err = postgres.Init(dsn, dbName, db.Tables()); err != nil {
		logger.WithError(err).Errorln("Failed to initialize postgres.")
		return err
	}
	endpoints, err := utils.ETCDEndpoints()
	if err != nil {
		logger.WithError(err).Errorln("Failed to get etcd endpoints.")
		return err
	}
	if err = etcd.Init(utils.ETCDPrefix(), endpoints, logger); err != nil {
		logger.WithError(err).Errorln("Failed to initialize ETCD.")
	}

	if err = t.initSupervisorClient(); err != nil {
		logger.WithError(err).Errorln("Failed to config supervisor client.")
		return err
	}
	return nil
}
func (t *TaskTable) initSupervisorClient() error {
	_, err := clients.InitSupervisorClient()
	return err
}

func wgClientList() ([]*clients.WgState, error) {
	var s []*clients.WgConfig
	resp, err := etcd.GetWithPrefix(wgConnConfigPrefix)
	if err != nil {
		return nil, err
	}
	for _, kv := range resp.Kvs {
		v := clients.WgConfig{}
		if err := json.Unmarshal(kv.Value, &v); err != nil {
			continue
		}
		s = append(s, &v)
	}
	return clients.NewWgClients(s), nil
}

func wgNamespaceMap() map[string]string {
	return clients.GetSupervisorClient().GetNamespaceMap()
}

func (table *TaskTable) NamespaceList() []string {
	if len(table.Config.Namespaces) > 0 {
		return table.Config.Namespaces
	}
	s := []string{}
	m := wgNamespaceMap()
	for n := range m {
		s = append(s, n)
	}
	return s
}

func (table *TaskTable) Run() {
	table.Logger.WithField("tables", len(table.TaskList)).Infoln("Running tasks")
	for _, t := range table.TaskList {
		go func() {
			t.Task(false)
			ticker := time.NewTicker(time.Second * time.Duration(t.Interval()))
			for {
				<-ticker.C
				// Reset ticker in case duration changed in config.
				ticker.Reset(time.Second * time.Duration(t.Interval()))
				t.Task(false)
			}
		}()
	}
	<-table.stopCh
	table.Logger.Infoln("Done running.")
}
