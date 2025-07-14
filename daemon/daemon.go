// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"context"
	"cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/accesskey"
	"cylonix/sase/daemon/analysis"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/daemon/device"
	"cylonix/sase/daemon/label"
	"cylonix/sase/daemon/login"
	"cylonix/sase/daemon/otp"
	"cylonix/sase/daemon/policy"
	"cylonix/sase/daemon/qrcode"
	"cylonix/sase/daemon/schedule"
	"cylonix/sase/daemon/tenant"
	"cylonix/sase/daemon/user"
	"cylonix/sase/daemon/vpn"
	"cylonix/sase/pkg/fwconfig"
	"cylonix/sase/pkg/interfaces"
	"cylonix/sase/pkg/ipdrawer"
	"cylonix/sase/pkg/logging"
	"cylonix/sase/pkg/metrics"
	"cylonix/sase/pkg/optional"
	"cylonix/sase/pkg/resources"
	"cylonix/sase/pkg/sendmail"
	"cylonix/sase/pkg/tools/es"
	pu "cylonix/sase/pkg/utils"
	pvpn "cylonix/sase/pkg/vpn"
	"cylonix/sase/pkg/wslog"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/cylonix/supervisor"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httplog/v2"

	"github.com/cylonix/utils"
	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	gviper "github.com/spf13/viper"
)

const (
	SocketPathDirectory = "/run/sase"
	SocketPath          = SocketPathDirectory + "/sase-manager.sock"
	ApiTimeout          = 60 * time.Second
	DefaultPort         = 9091
)

type Daemon struct {
	api             *api.StrictServer
	appTask         interfaces.AppSumTaskInterface
	cancel          context.CancelFunc
	cleaner         *common.Cleaner
	cmd             *cobra.Command
	ctx             context.Context
	dnsServer       interfaces.DNSServer
	domainName      string
	esClient        interfaces.EsClientInterface
	gConf           interfaces.GlobalConfigInterface
	resourceService interfaces.ResourceServiceInterface
	supervisor      *common.SupervisorService
	vpn             *vpn.VpnService
	viper           *gviper.Viper
}

type ServiceInterface interface {
	// GetName gets the service name
	Name() string

	// GetLogger gets the logger of the service.
	Logger() *logrus.Entry

	// Register register API handlers.
	Register(d *api.StrictServer) error

	// Start starts the service
	Start() error

	// Stop stops the service
	Stop()
}

var (
	services []ServiceInterface
)

// NewDaemon creates and returns a new Daemon.
func NewDaemon(ctx context.Context, cmd *cobra.Command, viper *gviper.Viper) (*Daemon, error) {
	utils.Init(viper)
	common.StartResourceInstance(daemonLogger)
	// Check critical settings first.
	setting := utils.ConfigCheckSetting{
		IPDrawer:  true,
		ETCD:      true,
		Postgres:  true,
	}
	config, err := utils.InitCfgFromViper(viper, setting)
	if err != nil {
		daemonLogger.WithError(err).Errorln("failed to init config")
		return nil, err
	}
	dCtx, cancel := context.WithCancel(ctx)
	cleaner := common.StartCleaner(daemonLogger)
	cleaner.SetCancelFunc(cancel)

	d := Daemon{
		domainName:    config.DomainName,
		cancel:        cancel,
		cmd:           cmd,
		cleaner:       cleaner,
		ctx:           dCtx,
		viper:         viper,
	}

	res := resources.NewResourceService(&d)
	d.resourceService = res

	// Send mail config.
	if err := sendmail.Init(viper, daemonLogger); err != nil {
		daemonLogger.WithError(err).Errorln("failed to init email send code service.")
		return nil, err
	}

	// Login cookie config.
	pu.LoginInit(d.viper)

	return &d, nil
}

func (d *Daemon) Viper() *gviper.Viper {
	return d.viper
}

// InstantiateAPI Create the API
func (d *Daemon) InstantiateAPI() error {
	viper := d.viper
	d.api = &api.StrictServer{Authenticator: &authenticator{}}
	d.supervisor = common.NewSupervisorService(d, d.resourceService, daemonLogger)
	fwService := common.GetFwConfigService()
	d.vpn = vpn.NewService(d, fwService, daemonLogger)
	wsAddr := net.JoinHostPort("0.0.0.0", "8070") // TODO: get from config.
	services = []ServiceInterface{
		accesskey.NewService(daemonLogger),
		analysis.NewService(d, daemonLogger),
		device.NewService(fwService, daemonLogger),
		label.NewService(fwService, daemonLogger),
		login.NewService(daemonLogger),
		otp.NewService(daemonLogger),
		policy.NewService(fwService, daemonLogger),
		qrcode.NewService(daemonLogger),
		tenant.NewService(daemonLogger),
		user.NewService(daemonLogger),
		wslog.NewService(wslog.Config{Addr: wsAddr}, daemonLogger), // websocket for logs
		d.supervisor,
		d.vpn,
	}
	logLevelFunctions := []func(logrus.Level){
		d.resourceService.SetLogLevel,
	}
	for _, s := range services {
		if err := s.Register(d.api); err != nil {
			log.Fatal(err)
		}
		if err := s.Start(); err != nil {
			log.Fatal(err)
		}
		d.cleaner.AddCleanUpFunc("stop "+s.Name(), s.Stop)
		logLevelFunctions = append(logLevelFunctions, func(level logrus.Level) {
			setHandlerLogLevel(level, s.Logger())
		})
	}

	if err := d.setLogLevel(logLevelFunctions); err != nil {
		return err
	}

	viper.OnConfigChange(func(in fsnotify.Event) {
		d.setLogLevel(logLevelFunctions)
	})

	cfg := viper.GetString("policy_config")
	if cfg != "" {
		if err := utils.LoadPolicyConfigure(cfg); err != nil {
			return err
		}
	}
	return nil
}

func (d *Daemon) setLogLevel(funcList []func(level logrus.Level)) error {
	viper := d.viper
	defaultLevel := logrus.ErrorLevel
	levelString := viper.GetString("log-level")
	if levelString != "" {
		level, err := logrus.ParseLevel(levelString)
		if err != nil {
			daemonLogger.WithError(err).WithField("level", levelString).Errorln("Failed to parse log level.")
			return err
		}
		defaultLevel = level
	}
	level := defaultLevel

	// Set log level to the filter level of any namespace so that log hooks can
	// see the logs to apply filters.
	cfg, err := utils.GetLogFilterConfig()
	if err != nil {
		return err
	}
	if cfg != nil {
		level = cfg.LogLevel()
	}
	for _, f := range funcList {
		f(level)
	}
	daemonLogger.WithFields(logrus.Fields{
		"log-level":     level.String(),
		"default-level": defaultLevel,
	}).Infoln("Set daemon logging level.")

	// Set up hooks.
	logging.AddZeroLogErrorHook(&logEntryHandler{})
	return logging.AddHooks(daemonLogger, &logEntryHandler{})
}
func (d *Daemon) checkEnv() error {
	_, err := os.Stat(SocketPathDirectory)
	if os.IsNotExist(err) {
		err = os.Mkdir(SocketPathDirectory, 0)
	}
	return err
}
func (d *Daemon) PrepareCheck() error {
	return d.checkEnv()
}

func (d *Daemon) getListeningAddr() string {
	addr := d.viper.GetString("listening_addr")
	if addr == "" {
		return fmt.Sprintf("0.0.0.0:%v", DefaultPort)
	}
	return addr
}

func (d *Daemon) ResourceService() interfaces.ResourceServiceInterface {
	return d.resourceService
}

func (d *Daemon) Serve() {
	swagger, err := api.GetSwagger()
	if err != nil {
		log.Fatalf("Error loading swagger spec\n: %s", err)
	}

	// Clear out the servers array in the swagger spec, that skips validating
	// that server names match. We don't know how this thing will be run.
	swagger.Servers = nil

	// This is how you set up a basic chi router
	r := chi.NewRouter()

	// Chi http logger.
	logger := httplog.NewLogger("cylonix-manager-daemon", httplog.Options{
		// JSON:             true,
		LogLevel:         slog.LevelDebug,
		Concise:          true,
		RequestHeaders:   true,
		MessageFieldName: "message",
		// TimeFieldFormat: time.RFC850,
		Tags: map[string]string{
			"version": "v2.0",
			"env":     "dev",
		},
		QuietDownRoutes: []string{
			"/",
		},
		QuietDownPeriod: 10 * time.Second,
		// SourceFieldName: "source",
	})
	r.Use(httplog.RequestLogger(logger))

	// Use validation middleware to check all requests against the schema.
	//r.Use(oapi_middleware.OapiRequestValidator(swagger))

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		d.Logger().WithField("request", r.RequestURI).Errorln("not found")
		w.WriteHeader(http.StatusNotFound)
	})

	handler := api.NewStrictHandler(d.api, nil)
	api.HandlerFromMuxWithBaseURL(handler, r, "/manager/v2")
	addr := d.getListeningAddr()
	s := &http.Server{
		Handler: r,
		Addr:    addr,
	}
	s.ReadTimeout = ApiTimeout
	s.WriteTimeout = ApiTimeout

	defer s.Shutdown(context.Background())

	d.Logger().WithField("addr", addr).Infoln("Starting daemon server.")

	// And we serve HTTP until the world ends.
	log.Fatal(s.ListenAndServe())
}

// Run blocks unless there is an error or it is interrupted.
func (d *Daemon) Run() error {
	taskQuitCh := make(chan string)
	if err := db.SetDaemonInterface(d); err != nil {
		return err
	}
	if err := db.InitDatabase(); err != nil {
		return err
	}
	if err := ipdrawer.InitIPdrawer(); err != nil {
		return err
	}
	if err := d.initSysAdmin(); err != nil {
		return fmt.Errorf("failed to init sys admin: %w", err)
	}

	url := utils.GetPrometheusURL()
	if url != "" {
		if err := metrics.InitPrometheusClient(url); err != nil {
			return err
		}
	}
	if err := d.PrepareCheck(); err != nil {
		return err
	}
	if err := d.InstantiateAPI(); err != nil {
		return err
	}

	esURL := utils.GetElasticsearchURL()
	var err error
	if esURL != "" {
		if d.esClient, err = es.NewEsClient(esURL, daemonLogger); err != nil {
			return err
		}
	}
	d.appTask = schedule.NewAppSummaryTask(d, d.esClient, taskQuitCh, daemonLogger)

	interruptCh := d.cleaner.RegisterSigHandler()
	d.cleaner.AddCleanUpFunc("remove socket path", func() { os.Remove(SocketPath) })
	if err := d.resourceService.Run(); err != nil {
		return err
	}

	// Running VPN server
	go func() {
		d.Logger().Infoln("Starting vpn server...")
		if err := pvpn.Run(vpn.NewNodeHandler(d.vpn), daemonLogger); err != nil {
			panic(err)
		}
		d.Logger().Infoln("Vpn server started...")
	}()

	go func() {
		d.Logger().Infoln("Starting daemon server...")
		d.Serve()
	}()

	d.Logger().Infoln("Server running. Waiting for signal to terminate...")
	// Blocks
	<-interruptCh

	// Interrupted
	return nil
}

func (d *Daemon) initSysAdmin() error {
	namespace, username, password, email, firstName, lastName := utils.GetCylonixAdminInfo()
	login, err := db.GetUserLoginByLoginNameFast("", username)
	if err != nil {
		if !errors.Is(err, db.ErrUserLoginNotExists) {
			return fmt.Errorf("failed to check if user login exists: %w", err)
		}
		// Fall through to create the user.
	} else {
		user := &types.User{}
		err := db.GetUser(login.UserID, user)
		if err == nil {
			if optional.Bool(user.IsSysAdmin) {
				d.Logger().Infof("Sys admin user %s already exists", username)
				return nil
			}
			return fmt.Errorf("user %s exists and is not sys admin", username)
		}
		if !errors.Is(err, db.ErrUserNotExists) {
			return fmt.Errorf("failed to check if user exists: %w", err)
		}
	}
	_, err = db.AddSysAdminUser(namespace, email, "", firstName + " " + lastName, username, password)
	if err != nil {
		return fmt.Errorf("failed to create sys admin user: %w", err)
	}
	d.Logger().Infof("Created sys admin user %s", username)
	return nil
}

func (d *Daemon) NamespaceInfo(namespace string) (*supervisor.FullNamespace, error) {
	namespaces, err := d.resourceService.NamespaceList()
	if err != nil {
		return nil, err
	}
	for _, ns := range namespaces {
		if ns.Name == namespace {
			return ns, nil
		}
	}
	return nil, fmt.Errorf("namespace %v does not exist", namespace)
}

func (d *Daemon) DefaultMeshMode(namespace string, log *logrus.Entry) string {
	if namespace == utils.DefaultNamespace {
		return string(models.MeshVpnModeSingle)
	}
	return string(models.MeshVpnModeTenant)
}

func (d *Daemon) EsClient() interfaces.EsClientInterface {
	return d.esClient
}

func (d *Daemon) AppTask() interfaces.AppSumTaskInterface {
	return d.appTask
}

func (d *Daemon) GlobalConfig() interfaces.GlobalConfigInterface {
	return d.gConf
}

func (d *Daemon) AddDnsRecord(hostname, ip string) error {
	return d.dnsServer.AddRecord(hostname, ip, d.domainName)
}

func (d *Daemon) DelDnsRecord(hostname, ip string) error {
	return d.dnsServer.DelRecord(hostname, ip, d.domainName)
}

func (d *Daemon) IsExitNodeSupported(namespace string, userID types.UserID, deviceID types.DeviceID) bool {
	return common.IsExitNodeSupported(namespace, userID, deviceID)
}

func (d *Daemon) Logger() *logrus.Entry {
	return daemonLogger
}

func (d *Daemon) VpnService() *vpn.VpnService {
	return d.vpn
}

func (d *Daemon) FwConfigService() fwconfig.ConfigService {
	return common.GetFwConfigService()
}
