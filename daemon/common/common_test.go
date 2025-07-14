// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"flag"
	"log"
	"os"
	"testing"

	"github.com/cylonix/utils"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var (
	testLogger = logrus.NewEntry(logrus.New())
)

func TestMain(m *testing.M) {
	flag.Parse()
	testInit()
	code := m.Run()
	testCleanup()
	os.Exit(code)
}

func testInit() {
	utils.Init(nil)
	if err := initTestDB(); err != nil {
		log.Fatalf("Failed to init test DB: %v", err)
	}
	if testing.Verbose() {
		testLogger.Logger.SetLevel(logrus.DebugLevel)
	} else {
		testLogger.Logger.SetLevel(logrus.ErrorLevel)
	}
}

func initTestDB() error {
	return db.InitEmulator(testing.Verbose())
}

func testCleanup() {
	db.CleanupEmulator()
}

func TestParseToken(t *testing.T) {
	token, _, _, _ := ParseToken(nil, "test-parse-token", "Test parse token", testLogger)
	assert.Nil(t, token)
	namespace := "test-namespace"
	userID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	auth := &utils.UserTokenData{
		Token:     "test-token",
		Namespace: namespace,
		UserID:    userID.UUID(),
	}
	token, namespace, userID, logger := ParseToken(auth, "test-parse-token", "Test parse token", testLogger)
	assert.NotNil(t, token)
	assert.Equal(t, auth.Namespace, namespace)
	assert.Equal(t, auth.UserID, userID.UUID())
	assert.NotNil(t, logger)
}
