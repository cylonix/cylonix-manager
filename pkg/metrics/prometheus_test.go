// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package metrics

import (
	"cylonix/sase/api/v2/models"
	"testing"

	"github.com/stretchr/testify/assert"
)

func resetInstance() {
	prometheusInstance = nil
}

func TestInitPrometheusClient_EmptyURL(t *testing.T) {
	err := InitPrometheusClient("")
	assert.Error(t, err)
}

func TestInitPrometheusClient_Valid(t *testing.T) {
	resetInstance()
	defer resetInstance()
	assert.NoError(t, InitPrometheusClient("http://127.0.0.1:9090"))
	assert.NotNil(t, prometheusInstance)
}

func TestSetPrometheusClient(t *testing.T) {
	resetInstance()
	defer resetInstance()
	e, err := NewPrometheusEmulator()
	assert.NoError(t, err)
	SetPrometheusClient(e)
	assert.NotNil(t, prometheusInstance)
}

func TestFirewallStats_NoInstance(t *testing.T) {
	resetInstance()
	_, err := FirewallStats("ns", "s")
	assert.ErrorIs(t, err, errNilPrometheusInstance)
}

func TestFirewallStats_Emulator(t *testing.T) {
	resetInstance()
	defer resetInstance()
	e, _ := NewPrometheusEmulator()
	SetPrometheusClient(e)
	s, err := FirewallStats("ns", "s")
	assert.NoError(t, err)
	assert.NotNil(t, s)
}

func TestNamespaceSummaryStats_NoInstance(t *testing.T) {
	resetInstance()
	_, err := NamespaceSummaryStats("ns", 1)
	assert.ErrorIs(t, err, errNilPrometheusInstance)
}

func TestNamespaceSummaryStats_Emulator(t *testing.T) {
	resetInstance()
	defer resetInstance()
	e, _ := NewPrometheusEmulator()
	SetPrometheusClient(e)
	_, err := NamespaceSummaryStats("ns", 1)
	assert.NoError(t, err)
}

func TestUserSummaryStats_NoInstance(t *testing.T) {
	resetInstance()
	_, err := UserSummaryStats("ns", "u", 1)
	assert.ErrorIs(t, err, errNilPrometheusInstance)
}

func TestUserSummaryStats_Emulator(t *testing.T) {
	resetInstance()
	defer resetInstance()
	e, _ := NewPrometheusEmulator()
	SetPrometheusClient(e)
	stats := models.SummaryStatsList{{}, {}}
	e.SetUserSummaryStats("ns", "u", stats)
	r, err := UserSummaryStats("ns", "u", 1)
	assert.NoError(t, err)
	assert.Len(t, r, 2)
}

func TestDeviceSummaryStats_NoInstance(t *testing.T) {
	resetInstance()
	_, err := DeviceSummaryStats("ns", "u", "d", 1)
	assert.ErrorIs(t, err, errNilPrometheusInstance)
}

func TestDeviceSummaryStats_Emulator(t *testing.T) {
	resetInstance()
	defer resetInstance()
	e, _ := NewPrometheusEmulator()
	SetPrometheusClient(e)
	e.SetDeviceSummaryStats("ns", "u", "d", []models.DeviceSummaryItem{{}})
	r, err := DeviceSummaryStats("ns", "u", "d", 1)
	assert.NoError(t, err)
	assert.Len(t, r, 1)
}

func TestDeviceRunTimeStats_NoInstance(t *testing.T) {
	resetInstance()
	_, err := DeviceRunTimeStats("ns", "u", "d", 5)
	assert.ErrorIs(t, err, errNilPrometheusInstance)
}

func TestDeviceRunTimeStats_Emulator(t *testing.T) {
	resetInstance()
	defer resetInstance()
	e, _ := NewPrometheusEmulator()
	SetPrometheusClient(e)
	r, err := DeviceRunTimeStats("ns", "u", "d", 5)
	assert.NoError(t, err)
	assert.Nil(t, r)
}

func TestEmulator_Query(t *testing.T) {
	e, _ := NewPrometheusEmulator()
	_, err := e.Query("")
	assert.Error(t, err)
}

func TestEmulator_OneMetricQuery(t *testing.T) {
	e, _ := NewPrometheusEmulator()
	assert.Equal(t, int64(0), e.OneMetricQuery("x"))
}

func TestEmulator_AggregationQuery(t *testing.T) {
	e, _ := NewPrometheusEmulator()
	v, err := e.AggregationQuery("fn", "m", nil, nil)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), v)
}

func TestCheckTimeUnit(t *testing.T) {
	assert.True(t, checkTimeUnit(TimeUnitMinutes))
	assert.True(t, checkTimeUnit(TimeUnitHour))
	assert.True(t, checkTimeUnit(TimeUnitDay))
	assert.True(t, checkTimeUnit(TimeUnitMonth))
	assert.False(t, checkTimeUnit('x'))
}

func TestLabelsToString(t *testing.T) {
	// Single-label ensures deterministic output
	s := labelsToString(map[string]string{"a": "b"})
	assert.Equal(t, `a="b"`, s)
	// Empty
	assert.Equal(t, "", labelsToString(nil))
}

func TestMax(t *testing.T) {
	assert.Equal(t, int64(5), max(5, 3))
	assert.Equal(t, int64(5), max(3, 5))
}

func TestCmdAndRateCmd(t *testing.T) {
	assert.Equal(t, `m{a="b"}`, cmd("m", `a="b"`))
	assert.Equal(t, `rate(m{a="b"}[5m])`, rateCmd("m", `a="b"`, 5))
}

func TestGenSumQueryStr(t *testing.T) {
	s := genSumQueryStr("x", "my_metric", map[string]string{"a": "b"})
	// Expected shape: "sum by(x)(my_metric{a='b'})"
	assert.Contains(t, s, "sum by(x)(")
	assert.Contains(t, s, "my_metric")
	assert.Contains(t, s, "a='b'")

	s = genSumQueryStr("", "my_metric", nil)
	assert.Contains(t, s, "sum(")
}

func TestSetTrafficStat(t *testing.T) {
	s := &models.FirewallStats{}
	setTrafficStat(s, 10, AllowCountMetric, Ingress)
	setTrafficStat(s, 11, DenyCountMetric, Ingress)
	setTrafficStat(s, 12, DropCountMetric, Ingress)
	setTrafficStat(s, 13, AllowBytesMetric, Ingress)
	setTrafficStat(s, 14, DenyBytesMetric, Ingress)
	setTrafficStat(s, 15, DropBytesMetric, Ingress)
	setTrafficStat(s, 20, AllowCountMetric, Egress)
	setTrafficStat(s, 21, DenyCountMetric, Egress)
	setTrafficStat(s, 22, DropCountMetric, Egress)
	setTrafficStat(s, 23, AllowBytesMetric, Egress)
	setTrafficStat(s, 24, DenyBytesMetric, Egress)
	setTrafficStat(s, 25, DropBytesMetric, Egress)
	assert.Equal(t, uint64(10), *s.AllowedRx)
	assert.Equal(t, uint64(11), *s.DeniedRx)
	assert.Equal(t, uint64(12), *s.DroppedRx)
	assert.Equal(t, uint64(13), *s.AllowedRxBytes)
	assert.Equal(t, uint64(14), *s.DeniedRxBytes)
	assert.Equal(t, uint64(15), *s.DroppedRxBytes)
	assert.Equal(t, uint64(20), *s.AllowedTx)
	assert.Equal(t, uint64(25), *s.DroppedTxBytes)
}

func TestQueryConditions_queryRange(t *testing.T) {
	qc := &queryConditions{totalRange: 3, step: 1}
	count := 0
	err := qc.queryRange(func(offset int) error {
		count++
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestEmulator_NamespaceSummaryStats(t *testing.T) {
	e, _ := NewPrometheusEmulator()
	r, err := e.NamespaceSummaryStats("ns", nil)
	assert.NoError(t, err)
	assert.Nil(t, r)
}

func TestEmulator_UserSummaryStats_Missing(t *testing.T) {
	e, _ := NewPrometheusEmulator()
	r, err := e.UserSummaryStats("ns", "u", nil)
	assert.NoError(t, err)
	assert.Nil(t, r)
}

func TestEmulator_DeviceSummaryStats_Missing(t *testing.T) {
	e, _ := NewPrometheusEmulator()
	r, err := e.DeviceSummaryStats("ns", "u", "d", nil)
	assert.NoError(t, err)
	assert.Nil(t, r)
}

func TestQueryDoErrorPropagation(t *testing.T) {
	// If q.err is already set, do returns 0 and does not crash.
	q := &query{err: assertErr{}}
	assert.Equal(t, int64(0), q.do("x"))
}

type assertErr struct{}

func (assertErr) Error() string { return "e" }
