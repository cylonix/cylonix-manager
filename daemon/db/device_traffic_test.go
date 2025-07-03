package db

import (
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDeviceTraffic(t *testing.T) {
	namespace := "namespace-test"
	wgName1 := "wg-name-1"
	wgName2 := "wg-name-3"

	deviceID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}

	equal := func (a int, b *uint64) bool {
		return assert.Equal(t, a, int(optional.Uint64(b)))
	}

	now := time.Now().Unix()
	_, err = UpdateDeviceTrafficByWgData(namespace, deviceID, now+60, 100, 100, wgName1)
	if !assert.Nil(t, err) {
		return
	}
	_, err = UpdateDeviceTrafficByWgData(namespace, deviceID, now+120, 200, 300, wgName1)
	if !assert.Nil(t, err) {
		return
	}
	_, err = UpdateDeviceTrafficByWgData(namespace, deviceID, now+180, 400, 500, wgName1)
	if !assert.Nil(t, err) {
		return
	}
	_, err = UpdateDeviceTrafficByWgData(namespace, deviceID, now+240, 100, 100, wgName1)
	if !assert.Nil(t, err) {
		return
	}
	_, err = UpdateDeviceTrafficByWgData(namespace, deviceID, now+180, 2400, 2500, wgName2)
	if !assert.Nil(t, err) {
		return
	}
	stat, err := GetDeviceWgTrafficStats(namespace, deviceID, wgName1)
	if assert.Nil(t, err) {
		equal(500, stat.RxBytes)
		equal(600, stat.TxBytes)
	}
	list, err := GetDeviceAllWgTrafficStats(namespace, deviceID)
	if assert.Nil(t, err) {
		assert.Equal(t, 2, len(list))
	}

	modelStat, err := DeviceAggregateTrafficStats(namespace, deviceID)
	if assert.Nil(t, err) {
		equal(2900, modelStat.RxBytes)
		equal(3100, modelStat.TxBytes)
	}
}
