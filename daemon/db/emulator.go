// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

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

type EmulatorSetting struct {
	Keycloak   bool
	Prometheus bool
	SendMail   bool
}

func InitSelectedEmulators(verbose bool, settings EmulatorSetting) error {
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
	if settings.Keycloak {
		kc, err := keycloak.NewEmulator()
		if err != nil {
			return err
		}
		keycloak.SetInstance(kc)
	}
	if settings.SendMail {
		sendmailE, err := sendmail.NewEmulator()
		if err != nil {
			return err
		}
		sendmail.SetInstance(sendmailE)
	}
	if settings.Prometheus {
		prometheusE, err := metrics.NewPrometheusEmulator()
		if err != nil {
			return err
		}
		metrics.SetPrometheusClient(prometheusE)
	}

	etcd.SetImpl(etcdE)
	redis.SetImpl(redisE)
	postgres.SetEmulator(true, verbose)
	return InitPGModels(false)
}

func CleanupEmulator() {
	postgres.CleanupEmulator()
}
