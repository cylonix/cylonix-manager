package daemon

import (
	"cylonix/sase/daemon/db"
	"flag"
	"log"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
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
	return db.InitEmulator(testing.Verbose())
}
