package db

import (
	"cylonix/sase/pkg/metrics"
	"cylonix/sase/pkg/sendmail"

	"github.com/cylonix/utils/etcd"
	"github.com/cylonix/utils/keycloak"
	"github.com/cylonix/utils/postgres"
	"github.com/cylonix/utils/redis"
)

var (
	dbEmulatorInitialized = false
)

func InitEmulator(verbose bool) error {
	if dbEmulatorInitialized {
		return nil
	}
	etcdE, err := etcd.NewEmulator()
	if err != nil {
		return err
	}
	redisE, err := redis.NewEmulator()
	if err != nil {
		return err
	}
	kc, err := keycloak.NewEmulator()
	if err != nil {
		return err
	}
	sendmailE, err := sendmail.NewEmulator()
	if err != nil {
		return err
	}
	prometheusE, err := metrics.NewPrometheusEmulator()
	if err != nil {
		return err
	}

	etcd.SetImpl(etcdE)
	redis.SetImpl(redisE)
	postgres.SetEmulator(true, verbose)
	keycloak.SetInstance(kc)
	sendmail.SetInstance(sendmailE)
	metrics.SetPrometheusClient(prometheusE)
	return InitPGModels(false)
}

func CleanupEmulator() {
	postgres.CleanupEmulator()
}
