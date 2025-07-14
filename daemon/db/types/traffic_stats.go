// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/optional"
)

type TrafficStats struct {
	RxBytes *uint64 `json:"rx_bytes,omitempty"`
	RxSpeed *uint64 `json:"rx_speed,omitempty"`
	TxBytes *uint64 `json:"tx_bytes,omitempty"`
	TxSpeed *uint64 `json:"tx_speed,omitempty"`
}

func NewTrafficStats(t *models.TrafficStats) TrafficStats {
	if t == nil {
		return TrafficStats{}
	}
	return TrafficStats{
		RxBytes: optional.CopyUint64P(t.RxBytes),
		TxBytes: optional.CopyUint64P(t.TxBytes),
		RxSpeed: optional.CopyUint64P(t.RxSpeed),
		TxSpeed: optional.CopyUint64P(t.TxSpeed),
	}
}
func (s TrafficStats) ToModel() *models.TrafficStats {
	return &models.TrafficStats{
		RxBytes: optional.CopyUint64P(s.RxBytes),
		TxBytes: optional.CopyUint64P(s.TxBytes),
		RxSpeed: optional.CopyUint64P(s.RxSpeed),
		TxSpeed: optional.CopyUint64P(s.TxSpeed),
	}
}
func (s *TrafficStats) Add(t *TrafficStats) {
	s.RxBytes = optional.AddUint64PIfNotNil(s.RxBytes, t.RxBytes)
	s.TxBytes = optional.AddUint64PIfNotNil(s.TxBytes, t.TxBytes)
	s.RxSpeed = optional.AddUint64PIfNotNil(s.RxSpeed, t.RxSpeed)
	s.TxSpeed = optional.AddUint64PIfNotNil(s.TxSpeed, t.TxSpeed)
}

type DeviceWgTrafficStatsID = ID
type DeviceWgTrafficStats struct {
	Model
	TrafficStats
	Namespace string   `gorm:"uniqueIndex:namespace_device_id_wg_server"`
	DeviceID  DeviceID `gorm:"uniqueIndex:namespace_device_id_wg_server"`
	WgServer  string   `gorm:"uniqueIndex:namespace_device_id_wg_server"`
	LastSeen  int64
}

func NewDeviceTrafficStats(namespace string, deviceID DeviceID, m *models.WgTrafficStats) *DeviceWgTrafficStats {
	return &DeviceWgTrafficStats{
		Namespace:    namespace,
		DeviceID:     deviceID,
		TrafficStats: NewTrafficStats(&m.TrafficStats),
		WgServer:     m.WgServer,
	}
}
func (s *DeviceWgTrafficStats) ToModel() *models.WgTrafficStats {
	if s == nil {
		return nil
	}
	return &models.WgTrafficStats{
		TrafficStats: *s.TrafficStats.ToModel(),
		UpdatedAt:    s.UpdatedAt.Unix(),
		WgServer:     s.WgServer,
	}
}
