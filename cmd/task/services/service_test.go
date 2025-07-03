package services

import (
	"cylonix/sase/daemon/db"
	"flag"
	"log"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
)

var (
	testLogger = logrus.NewEntry(logrus.New())
)

func testSetup() error {
	if err := db.InitEmulator(testing.Verbose()); err != nil {
		return err
	}
	if testing.Verbose() {
		testLogger.Logger.SetLevel(logrus.DebugLevel)
	} else {
		testLogger.Logger.SetLevel(logrus.ErrorLevel)
	}
	return nil
}

func testCleanup() {
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