// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/daemon/db/types"
	"fmt"
	"reflect"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/postgres"
)

func initPGModels(dropBeforeMigrate bool, models ...interface{}) error {
	pg, err := postgres.Connect()
	if err != nil || pg == nil {
		logger.WithError(err).Errorln("Failed to connect to database.")
		return ErrPGConnection
	}
	if dropBeforeMigrate {
		logger.Infoln("Drop tables before migrating.")
		for _, m := range models {
			table := fmt.Sprintf("%T", m)
			log := logger.WithField("table", table)
			log.Infoln("Check if to drop many to many relationship table first.")
			if d, ok := m.(types.DropManyToManyTables); ok {
				log.Infoln("Drop many to many relationship table.")
				if err = d.DropManyToMany(pg); err != nil {
					log.WithError(err).Errorln("Failed to drop model's many to many relationship table.")
					return err
				}
			}
		}
		if err = pg.Migrator().DropTable(models...); err != nil {
			logger.WithError(err).Errorln("Failed to drop models.")
			return err
		}
	}
	for _, v := range models {
		if err := pg.AutoMigrate(v); err != nil {
			logger.WithError(err).Errorf("Failed to auto migrate '%T'.", v)
			return err
		}
	}
	return nil
}

func Tables() []interface{} {
	return []interface{}{
		&types.User{},
		&types.UserApproval{},
		&types.AccessKey{},
		&types.AlarmMessage{},
		&types.Alert{},
		&types.Device{},
		&types.DeviceApproval{},
		&types.DeviceCapability{},
		&types.DeviceWgTrafficStats{},
		&types.FriendRequest{},
		&types.FwRule{},
		&types.FwStat{},
		&types.Label{},
		&types.NamespaceSummaryStat{},
		&types.Policy{}, // Policies table needs to be created before path selects.
		&types.PathSelect{},
		&types.PolicyTarget{},
		&types.TenantConfig{},
		&types.TenantApproval{},
		&types.HistoryEntry{},
		&types.UserBaseInfo{},
		&types.UserLogin{},
		&types.UserSummaryStat{},
		&types.UserTier{},
		&types.WgInfo{},
		&types.WgNode{},
		&utils.UserTokenData{},
		&utils.OauthStateTokenData{},
	}
}

func InitPGModels(dropBeforeMigrate bool) error {
	return initPGModels(dropBeforeMigrate, Tables()...)
}

func InitPGOtherModels(dropBeforeMigrate bool, models ...interface{}) error {
	return initPGModels(dropBeforeMigrate, models...)
}

func InitPGModelsByNames(dropBeforeMigrate bool, names, namespaces []string) error {
	var tables []interface{}
	for _, name := range names {
		found := false
		for _, m := range Tables() {
			if reflect.ValueOf(m).Elem().Type().Name() == name {
				tables = append(tables, m)
				found = true
			}
		}
		if !found {
			return fmt.Errorf("cannot find table for '%v'", name)
		}
	}
	return initPGModels(dropBeforeMigrate, tables...)
}
