package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"errors"
	"time"

	"github.com/cylonix/utils/postgres"
	"gorm.io/gorm"
)

func GetDeviceWgTrafficStats(namespace string, deviceID types.DeviceID, wgServer string) (*types.DeviceWgTrafficStats, error) {
	ret := &types.DeviceWgTrafficStats{}
	if err := postgres.SelectFirst(ret,
		"namespace = ? and device_id = ? and wg_server = ?",
		namespace, deviceID, wgServer); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrDeviceTrafficNotExists
		}
		return nil, err
	}
	return ret, nil
}

func DeleteDeviceWgTrafficStats(namespace string, idList []types.DeviceWgTrafficStatsID) error {
	var stats []types.DeviceWgTrafficStats
	for _, id := range idList {
		if id.IsNil() {
			continue
		}
		stats = append(stats, types.DeviceWgTrafficStats{Model: types.Model{ID: id}})
	}
	if len(stats) <= 0 {
		return nil
	}
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	return tx.Delete(stats).Error
}

func CreateDeviceWgTrafficStats(s *types.DeviceWgTrafficStats) error {
	if err := s.Model.SetIDIfNil(); err != nil {
		return err
	}
	return postgres.Create(s)
}

// GetDeviceAllWgTrafficStats gets a list of the traffic stats for the same device.
func GetDeviceAllWgTrafficStats(namespace string, deviceID types.DeviceID) ([]types.DeviceWgTrafficStats, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return nil, err
	}
	list := []types.DeviceWgTrafficStats{}
	cond := types.DeviceWgTrafficStats{Namespace: namespace, DeviceID: deviceID}
	err = pg.Model(&types.DeviceWgTrafficStats{}).
		Where(&cond).
		Find(&list).Error
	return list, err
}

// DeviceAggregateTrafficStats aggregate the traffic stats of all wg servers.
// TODO: use raw SQL to do the add directly in DB.
func DeviceAggregateTrafficStats(namespace string, deviceID types.DeviceID) (*models.TrafficStats, error) {
	t := &types.TrafficStats{}
	list, err := GetDeviceAllWgTrafficStats(namespace, deviceID)
	if err != nil {
		return nil, err
	}
	for _, v := range list {
		t.Add(&v.TrafficStats)
	}
	return t.ToModel(), nil
}

// Never expect an int64 to wrap around. If current is less than the last
// it means the wg gateway has reset the counter. Hence simply use it
// as the delta.
func delta(last *uint64, current uint64) (uint64, *uint64) {
	delta, newTotal := uint64(0), current
	if last != nil {
		if *last < current {
			delta = current - *last
		} else {
			delta = current
			newTotal = current + *last
		}
	}
	return delta, &newTotal
}

// UpdateDeviceTrafficByWgData updates the traffic stats from a wg-server.
// If current stat is less than the last recorded it means the wg gateway has
// reset the counter.
func UpdateDeviceTrafficByWgData(namespace string, deviceID types.DeviceID,
	lastSeen int64, rxBytes, txBytes uint64, wgServer string,
) (*types.DeviceWgTrafficStats, error) {

	s, err := GetDeviceWgTrafficStats(namespace, deviceID, wgServer)
	if err != nil {
		if !errors.Is(err, ErrDeviceTrafficNotExists) {
			return nil, err
		}
		m := &models.WgTrafficStats{
			TrafficStats: models.TrafficStats{
				RxBytes: optional.Uint64P(rxBytes),
				TxBytes: optional.Uint64P(txBytes),
			},
			WgServer: wgServer,
		}
		s = types.NewDeviceTrafficStats(namespace, deviceID, m)
		s.LastSeen = lastSeen
		if err = CreateDeviceWgTrafficStats(s); err != nil {
			return nil, err
		}
		return s, nil
	}

	now := time.Now().Unix()
	deltaTime := now - s.UpdatedAt.Unix()
	var rxDelta, txDelta uint64
	rxDelta, s.RxBytes = delta(s.RxBytes, rxBytes)
	txDelta, s.TxBytes = delta(s.TxBytes, txBytes)

	if deltaTime > 0 {
		s.RxSpeed = optional.Uint64P(rxDelta / uint64(deltaTime))
		s.TxSpeed = optional.Uint64P(txDelta / uint64(deltaTime))
	}

	update := &types.DeviceWgTrafficStats{
		TrafficStats: s.TrafficStats,
		LastSeen:     lastSeen,
	}
	cond := types.DeviceWgTrafficStats{
		Namespace: namespace,
		DeviceID:  deviceID,
		WgServer:  wgServer,
	}
	if err = postgres.Updates(&types.DeviceWgTrafficStats{}, update, &cond); err != nil {
		return nil, err
	}
	return s, nil
}
