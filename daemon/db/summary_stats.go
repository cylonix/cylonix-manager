// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"errors"

	"github.com/cylonix/utils/postgres"
	"gorm.io/gorm"
)

func newSummaryStats(s *models.SummaryStats) types.SummaryStats {
	return types.SummaryStats{
		AlarmCount:        s.AlarmCount,
		AlarmUnread:       s.AlarmUnread,
		UserCount:         s.UserCount,
		OnlineUserCount:   s.OnlineUserCount,
		DeviceCount:       s.DeviceCount,
		OnlineDeviceCount: s.OnlineDeviceCount,
		LabelCount:        s.LabelCount,
		PolicyCount:       s.PolicyCount,
		TrafficStats:      types.NewTrafficStats(s.TrafficStats),
	}
}

func LastUserSummaryStat(userID types.UserID) (*models.SummaryStats, error) {
	s := &types.UserSummaryStat{}
	if err := postgres.SelectFirst(s, &types.UserSummaryStat{
		UserID: userID,
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &models.SummaryStats{}, nil
		}
		return nil, err
	}
	return s.SummaryStats.ToModel(), nil
}

func CreateOrUpdateUserSummaryStat(namespace string, userID types.UserID, s *models.SummaryStats) error {
	if userID == types.NilID {
		return ErrBadParams
	}
	us := &types.UserSummaryStat{
		UserID:       userID,
		SummaryStats: newSummaryStats(s),
	}
	var count int64
	db, err := postgres.Connect()
	if err != nil || db == nil {
		return ErrPGConnection
	}
	db = db.Model(&types.UserSummaryStat{}).Where("user_id = ?", userID)
	if err := db.Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return db.Updates(&types.UserSummaryStat{
			SummaryStats: newSummaryStats(s),
		}).Error
	}
	id, err := types.NewID()
	if err != nil {
		return err
	}
	us.ID = id
	return db.Create(&us).Error
}

func LastNamespaceSummaryStat(namespace string) (*models.SummaryStats, error) {
	s := &types.NamespaceSummaryStat{}
	if err := postgres.SelectFirst(s, &types.NamespaceSummaryStat{
		Namespace: namespace,
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &models.SummaryStats{}, nil
		}
		return nil, err
	}
	return s.SummaryStats.ToModel(), nil
}

func CreateOrUpdateNamespaceSummaryStat(namespace string, s *models.SummaryStats) error {
	ns := &types.NamespaceSummaryStat{
		Namespace:    namespace,
		SummaryStats: newSummaryStats(s),
	}
	var count int64
	db, err := postgres.Connect()
	if err != nil || db == nil {
		return ErrPGConnection
	}
	query := &types.NamespaceSummaryStat{Namespace: namespace}
	db.Model(query).Where(query).Count(&count)
	if count > 0 {
		return db.Updates(&ns).Error
	}
	id, err := types.NewID()
	if err != nil {
		return err
	}
	ns.ID = id
	return db.Create(&ns).Error
}
