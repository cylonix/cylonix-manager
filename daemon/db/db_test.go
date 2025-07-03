package db

import (
	"cylonix/sase/daemon/db/types"
	"errors"
	"flag"
	"log"
	"os"
	"testing"

	"github.com/cylonix/utils"
	"github.com/sirupsen/logrus"
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
	if !testing.Verbose() {
		logger.Logger.SetLevel(logrus.ErrorLevel)
	}
}

func initTestDB() error {
	return InitEmulator(testing.Verbose())
}

func testCleanup() {
	os.Remove("cover.out")
	CleanupEmulator()
}

func createUserTierForTest() (*types.UserTier, error) {
	tier, err := GetUserTierByName("test-tier")
	if err != nil && !errors.Is(err, ErrUserTierNotExists) {
		return nil, err
	}
	if err == nil {
		return tier, nil
	}
	tier = &types.UserTier{
		Name:           "test-tier",
		Description:    "test-tier-description",
		MaxUserCount:   100,
		MaxDeviceCount: 100,
	}
	return CreateUserTier(tier)
}
