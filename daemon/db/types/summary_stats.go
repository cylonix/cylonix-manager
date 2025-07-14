// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import "cylonix/sase/api/v2/models"


type NamespaceSummaryStatID = ID
type UserSummaryStatID = ID

type SummaryStats struct {
	AlarmCount        *int `json:"alarm_count,omitempty"`
	AlarmUnread       *int `json:"alarm_unread,omitempty"`
	DeviceCount       *int `json:"device_count,omitempty"`
	LabelCount        *int `json:"label_count,omitempty"`
	OnlineDeviceCount *int `json:"online_device_count,omitempty"`
	OnlineUserCount   *int `json:"online_user_count,omitempty"`
	PolicyCount       *int `json:"policy_count,omitempty"`
	UserCount         *int `json:"user_count,omitempty"`
	TrafficStats
}

type UserSummaryStat struct {
	Model // ID is the same as user ID
	SummaryStats
	Namespace string
	UserID UserID `gorm:"type:uuid;uniqueIndex" json:"user_id"` // to form user has one relation.
}

type NamespaceSummaryStat struct {
	Model // ID is the same as tenant ID
	SummaryStats
	Namespace string `gorm:"uniqueIndex" json:"namespace"`
}

func (s *SummaryStats) ToModel() *models.SummaryStats {
	return &models.SummaryStats{
		AlarmCount:        s.AlarmCount,
		AlarmUnread:       s.AlarmUnread,
		UserCount:         s.UserCount,
		OnlineUserCount:   s.OnlineUserCount,
		DeviceCount:       s.DeviceCount,
		OnlineDeviceCount: s.OnlineDeviceCount,
		LabelCount:        s.LabelCount,
		PolicyCount:       s.PolicyCount,
		TrafficStats:      s.TrafficStats.ToModel(),
	}
}
