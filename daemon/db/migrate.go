// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/daemon/db/types"
	"log"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/postgres"
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

var (
	migrations = []*gormigrate.Migration{
		{
			ID: "202410310000",
			Migrate: func(tx *gorm.DB) error {
				if err := tx.Migrator().DropIndex(&types.WgInfo{}, "idx_wg_infos_machine_key"); err != nil {
					log.Printf("Failed to drop the wg_infos addresses column: %v", err)
				}
				if err := tx.Migrator().DropIndex(&types.WgInfo{}, "idx_wg_infos_addresses_"); err != nil {
					log.Printf("Failed to drop the wg_infos addresses column: %v", err)
				}
				if err := tx.Migrator().DropIndex(&types.WgNode{}, "idx_wg_nodes_addresses_"); err != nil {
					log.Printf("Failed to drop the wg_nodes addresses column: %v", err)
				}
				if err := tx.Migrator().DropIndex(&types.WgNode{}, "wg_node_namespace_stable_id"); err != nil {
					log.Printf("Failed to drop the wg_infos stable_id column: %v", err)
				}
				if err := tx.Migrator().DropColumn(&types.WgNode{}, "StableID"); err != nil {
					log.Printf("Failed to drop the wg_infos stable_id column: %v", err)
				}
				return tx.AutoMigrate(Tables()...)
			},
			Rollback: func(db *gorm.DB) error { return nil },
		},
		{
			ID: "202411210000",
			Migrate: func(tx *gorm.DB) error {
				return tx.AutoMigrate(&types.Device{})
			},
			Rollback: func(db *gorm.DB) error { return nil },
		},
		{
			ID: "202412060000",
			Migrate: func(tx *gorm.DB) error {
				return tx.AutoMigrate(&types.FwRule{})
			},
			Rollback: func(db *gorm.DB) error { return nil },
		},
		{
			ID: "202503280000",
			Migrate: func(tx *gorm.DB) error {
				return tx.AutoMigrate(&utils.OauthStateTokenData{})
			},
			Rollback: func(db *gorm.DB) error { return nil },
		},
		{
			ID: "202505170000",
			Migrate: func(tx *gorm.DB) error {
				return tx.AutoMigrate(
					&types.Policy{},
					&types.TenantConfig{},
					&types.User{},
					&types.UserTier{},
				)
			},
			Rollback: func(db *gorm.DB) error { return nil },
		},
		{
			ID: "202505180000",
			Migrate: func(tx *gorm.DB) error {
				log.Printf(`
				Migrating to add additional node info in OauthStateTokenData
				and add network domain field to HistoryEntry
				`)
				return tx.AutoMigrate(
					&utils.OauthStateTokenData{},
					&types.HistoryEntry{},
				)
			},
			Rollback: func(db *gorm.DB) error { return nil },
		},
		{
			ID: "202505191300",
			Migrate: func(tx *gorm.DB) error {
				log.Printf(`
				Migrating to add additional network domain info in Device,
				Alarm and Alert
				`)
				return tx.AutoMigrate(
					&types.Device{},
					&types.AlarmMessage{},
					&types.Alert{},
				)
			},
			Rollback: func(db *gorm.DB) error { return nil },
		},
		{
			ID: "202505201300",
			Migrate: func(tx *gorm.DB) error {
				log.Printf(`
				Migrating to add network domain to user token data.
				`)
				return tx.AutoMigrate(
					&utils.UserTokenData{},
				)
			},
			Rollback: func(db *gorm.DB) error { return nil },
		},
		{
			ID: "202506101300",
			Migrate: func(tx *gorm.DB) error {
				log.Printf(`
					Migrating to add user login fields.
				`)
				return tx.AutoMigrate(
					&types.UserLogin{},
				)
			},
			Rollback: func(db *gorm.DB) error { return nil },
		},
		{
			ID: "202507270900",
			Migrate: func(tx *gorm.DB) error {
				log.Printf(`
					Migrating to add user invite support.
				`)
				return tx.AutoMigrate(
					&types.UserBaseInfo{},
					&types.UserInvite{},
					&utils.OauthStateTokenData{},
				)
			},
			Rollback: func(db *gorm.DB) error { return nil },
		},
	}
)

func InitDatabase() error {
	if err := postgres.CheckAndCreatedDB(); err != nil {
		return err
	}

	tx, err := getPGconn()
	if err != nil {
		return err
	}

	return gormigrate.New(tx, gormigrate.DefaultOptions, migrations).Migrate()
}
