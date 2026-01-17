// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"context"
	"cylonix/sase/daemon/db"
	"flag"
	"log"
	"os"
	"testing"

	"github.com/cylonix/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	flag.Parse()
	testInit()
	os.Exit(m.Run())
}

func testInit() {
	if err := initTestDB(); err != nil {
		log.Fatalf("Failed to init test DB: %v", err)
	}
	if !testing.Verbose() {
		daemonLogger.Logger.SetLevel(logrus.ErrorLevel)
	}
}

func initTestDB() error {
	return db.InitSelectedEmulators(testing.Verbose(), db.EmulatorSetting{
		// Not enabling optional emulators
	})
}

func TestInitSysAdmin(t *testing.T) {
	viper.Set("base_url", "http://localhost")
	d, err := NewDaemon(context.Background(), nil, nil, &utils.ConfigCheckSetting{})
	assert.Nil(t, err)
	err = d.initSysAdmin()
	assert.Nil(t, err)
}