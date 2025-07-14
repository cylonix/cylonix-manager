// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package analysis

import (
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"flag"
	"log"
	"os"
	"testing"

	"github.com/cylonix/utils"
	"github.com/sirupsen/logrus"
)

var (
	testLogger    = logrus.NewEntry(logrus.New())
	testNamespace = "test-namespace"
	testUserID    types.UserID
	testUsername  = "test-username"
	testUserToken *utils.UserTokenData
)

func testSetup() (err error) {
	utils.Init(nil)
	if err = db.InitEmulator(testing.Verbose()); err != nil {
		return err
	}
	if !testing.Verbose() {
		testLogger.Logger.SetLevel(logrus.ErrorLevel)
	}
	testUserID, err = types.NewID()
	if err != nil {
		return err
	}

	token := utils.NewUserToken(testNamespace)
	testUserToken = &utils.UserTokenData{
		Token:         token.Token,
		TokenTypeName: token.Name(),
		Namespace:     testNamespace,
		UserID:        testUserID.UUID(),
		Username:      testUsername,
	}
	if err := token.Create(testUserToken); err != nil {
		return err
	}
	return nil
}
func testCleanup() {
	os.Remove("cover.out")
	db.CleanupEmulator()
}

func TestMain(m *testing.M) {
	flag.Parse()
	if err := testSetup(); err != nil {
		log.Fatalf("Failed to setup test: %v.", err)
	}
	code := m.Run()
	testCleanup()
	os.Exit(code)
}
