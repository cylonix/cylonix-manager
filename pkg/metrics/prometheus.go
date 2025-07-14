// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package metrics

import (
	"context"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/optional"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
)

const (
	AllowCountMetric = "ep_allow_count"
	AllowBytesMetric = "ep_allow_bytes"
	DenyCountMetric  = "ep_deny_count"
	DenyBytesMetric  = "ep_deny_bytes"
	DropCountMetric  = "ep_drop_count"
	DropBytesMetric  = "ep_drop_bytes"
	Egress           = "Egress"
	Ingress          = "Ingress"
	TimeUnitMinutes  = 'm'
	TimeUnitHour     = 'h'
	TimeUnitDay      = 'd'
	TimeUnitMonth    = 'M'
)

type PrometheusClientInterface interface {
	Query(query string) (model.Value, error)
	AggregationQuery(fn, metric string, labels map[string]string, qc *queryConditions) (int64, error)
	FirewallStats(namespace, srcID string) (*models.FirewallStats, error)
	UserSummaryStats(namespace, userID string, qc *queryConditions) ([]models.SummaryStats, error)
	DeviceSummaryStats(namespace, userID, deviceID string, qc *queryConditions) ([]models.DeviceSummaryItem, error)
	NamespaceSummaryStats(namespace string, qc *queryConditions) ([]models.SummaryStats, error)
	DeviceRunTimeStats(namespace, userID, deviceID string, timeRange int) (*models.DeviceSummaryItem, error)
}

type prometheusClient struct {
	promAPI v1.API
}

var (
	prometheusInstance   PrometheusClientInterface
	trafficDirections    = []string{Egress, Ingress}
	trafficTaiMetricList = []string{
		AllowCountMetric,
		AllowBytesMetric,
		DenyCountMetric,
		DenyBytesMetric,
		DropCountMetric,
		DropBytesMetric,
	}
)

var (
	errInvalidQueryRange     = errors.New("invalid query range")
	errNilPrometheusInstance = errors.New("prometheus instance is nil")
)

type queryConditions struct {
	totalRange int
	subRange   int
	offset     int
	step       int
	timeUnit   byte
}

func (qc *queryConditions) queryRange(do func(offset int) error) error {
	for i := 1; i <= qc.totalRange; i += qc.step {
		qc.offset = i
		if err := do(i); err != nil {
			return err
		}
	}
	return nil
}

func InitPrometheusClient(url string) error {
	if url == "" {
		return errors.New("invalid prometheus url")
	}
	client, err := api.NewClient(api.Config{
		Address: url,
	})
	if err != nil {
		return err
	}

	promClient := &prometheusClient{promAPI: v1.NewAPI(client)}
	SetPrometheusClient(promClient)
	return nil
}

func SetPrometheusClient(promClient PrometheusClientInterface) {
	prometheusInstance = promClient
}

func (client *prometheusClient) Query(query string) (model.Value, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, warnings, err := client.promAPI.Query(ctx, query, time.Now())
	if err != nil {
		return nil, err
	}
	if len(warnings) > 0 {
		errStr := fmt.Sprintf("warnings: %v\n", warnings)
		return nil, errors.New(errStr)
	}
	return result, nil
}

func setTrafficStat(traffic *models.FirewallStats, v int64, metric, dir string) {
	val := optional.Uint64P(uint64(v))
	switch dir + metric {
	case Ingress + AllowCountMetric:
		traffic.AllowedRx = val
	case Ingress + DenyCountMetric:
		traffic.DeniedRx = val
	case Ingress + DropCountMetric:
		traffic.DroppedRx = val
	case Ingress + AllowBytesMetric:
		traffic.AllowedRxBytes = val
	case Ingress + DenyBytesMetric:
		traffic.DeniedRxBytes = val
	case Ingress + DropBytesMetric:
		traffic.DroppedRxBytes = val
	case Egress + AllowCountMetric:
		traffic.AllowedTx = val
	case Egress + DenyCountMetric:
		traffic.DeniedTx = val
	case Egress + DropCountMetric:
		traffic.DroppedTx = val
	case Egress + AllowBytesMetric:
		traffic.AllowedTxBytes = val
	case Egress + DenyBytesMetric:
		traffic.DeniedTxBytes = val
	case Egress + DropBytesMetric:
		traffic.DroppedTxBytes = val
	}
}

func genSumQueryStr(groupBy string, metric string, labels map[string]string) string {
	queryBuilder := strings.Builder{}

	queryBuilder.WriteString("sum")
	if groupBy != "" {
		queryBuilder.WriteString(" by(" + groupBy + ")")
	}
	queryBuilder.WriteString("(")
	queryBuilder.WriteString(metric)
	queryBuilder.WriteString("{")
	i := 0
	for lbl, val := range labels {
		if i > 0 {
			queryBuilder.WriteString(",")
		}
		queryBuilder.WriteString(lbl + "='" + val + "'")
		i++
	}
	queryBuilder.WriteString("})")
	return queryBuilder.String()
}

func (client *prometheusClient) FirewallStats(namespace, srcId string) (*models.FirewallStats, error) {
	stats := &models.FirewallStats{}
	labels := make(map[string]string)
	groupBy := ""

	labels["namespace"] = namespace
	if srcId != "" {
		labels["src_identity"] = srcId
		// Only group by src ID if src ID is set.
		// In the case of getting all the user stats, we want the aggregation
		// to be done in prometheus instead of returning potentially thousands
		// of entries to the client.
		groupBy = "src_identity"
	}
	for _, metric := range trafficTaiMetricList {
		for _, direction := range trafficDirections {
			labels["direction"] = direction
			query := genSumQueryStr(groupBy, metric, labels)
			format := "query prometheus failed query=" + query + ": %w"
			result, err := client.Query(query)
			if err != nil {
				return nil, fmt.Errorf(format, err)
			}
			total := int64(0)
			val := result.(model.Vector)
			for _, ret := range val {
				total += int64(ret.Value)
			}
			setTrafficStat(stats, total, metric, direction)
		}
	}
	return stats, nil
}

// Empty srcID to get the aggregated traffic stats for all the users
// of the namespace
func FirewallStats(namespace, srcID string) (*models.FirewallStats, error) {
	if prometheusInstance == nil {
		return nil, errNilPrometheusInstance
	}
	return prometheusInstance.FirewallStats(namespace, srcID)
}

type query struct {
	client *prometheusClient
	qc     *queryConditions
	labels map[string]string
	err    error
}

func newQuery(client *prometheusClient, qc *queryConditions, labels map[string]string) *query {
	return &query{
		client: client,
		labels: labels,
		qc:     qc,
	}
}

func (q *query) do(name string) int64 {
	if q.err != nil {
		return 0
	}
	v, err := q.client.AggregationQuery("max_over_time", name, q.labels, q.qc)
	if err != nil {
		q.err = err
		return 0
	}
	return v
}

func (client *prometheusClient) NamespaceSummaryStats(namespace string, qc *queryConditions) (list []models.SummaryStats, err error) {
	if qc.totalRange < 1 {
		return nil, errInvalidQueryRange
	}
	labels := map[string]string{"namespace": namespace}
	q := newQuery(client, qc, labels)
	err = qc.queryRange(func(_ int) error {
		s := models.SummaryStats{
			DeviceCount:       optional.IntP(int(q.do(NamespaceSummaryDeviceCount))),
			LabelCount:        optional.IntP(int(q.do(NamespaceSummaryLabelCount))),
			PolicyCount:       optional.IntP(int(q.do(NamespaceSummaryPolicyCount))),
			OnlineDeviceCount: optional.IntP(int(q.do(NamespaceSummaryUserCount))),
			UserCount:         optional.IntP(int(q.do(NamespaceSummaryUserCount))),
			OnlineUserCount:   optional.IntP(int(q.do(NamespaceSummaryOnlineUserCount))),
			AlarmCount:        optional.IntP(int(q.do(NamespaceSummaryAlarmCount))),
			TrafficStats: &models.TrafficStats{
				RxBytes: optional.Uint64P(uint64(q.do(NamespaceSummaryRxBytes))),
				TxBytes: optional.Uint64P(uint64(q.do(NamespaceSummaryTxBytes))),
			},
		}
		list = append(list, s)
		return q.err
	})
	if err != nil {
		return nil, err
	}
	return
}
func NamespaceSummaryStats(namespace string, day int) ([]models.SummaryStats, error) {
	if prometheusInstance == nil {
		return nil, errNilPrometheusInstance
	}
	qc := queryConditions{
		subRange:   1,
		timeUnit:   TimeUnitDay,
		totalRange: day,
		step:       1,
	}
	return prometheusInstance.NamespaceSummaryStats(namespace, &qc)
}
func (client *prometheusClient) UserSummaryStats(namespace, userID string, qc *queryConditions) (list []models.SummaryStats, err error) {
	if qc.totalRange < 1 {
		return nil, errInvalidQueryRange
	}
	labels := map[string]string{
		"namespace": namespace,
		"user_id":   userID,
	}
	q := newQuery(client, qc, labels)
	err = qc.queryRange(func(_ int) error {
		s := models.SummaryStats{
			UserCount:         optional.IntP(1),
			DeviceCount:       optional.IntP(int(q.do(UserSummaryDeviceCount))),
			LabelCount:        optional.IntP(int(q.do(UserSummaryLabelCount))),
			PolicyCount:       optional.IntP(int(q.do(UserSummaryPolicyCount))),
			AlarmCount:        optional.IntP(int(q.do(UserSummaryAlarmCount))),
			OnlineDeviceCount: optional.IntP(int(q.do(UserSummaryOnlineCount))),
			TrafficStats: &models.TrafficStats{
				RxBytes: optional.Uint64P(uint64(q.do(UserSummaryRxBytes))),
				TxBytes: optional.Uint64P(uint64(q.do(UserSummaryTxBytes))),
			},
		}
		list = append(list, s)
		return q.err
	})
	if err != nil {
		return nil, err
	}
	return
}
func UserSummaryStats(namespace, userID string, day int) ([]models.SummaryStats, error) {
	if prometheusInstance == nil {
		return nil, errNilPrometheusInstance
	}
	qc := queryConditions{
		subRange:   1,
		timeUnit:   TimeUnitDay,
		totalRange: day,
		step:       1,
	}
	return prometheusInstance.UserSummaryStats(namespace, userID, &qc)
}
func (client *prometheusClient) DeviceSummaryStats(namespace, userID, deviceID string, qc *queryConditions) (list []models.DeviceSummaryItem, err error) {
	if qc.totalRange < 1 {
		return nil, errInvalidQueryRange
	}
	labels := map[string]string{
		"namespace": namespace,
		"user_id":   userID,
		"device_id": deviceID,
	}
	q := newQuery(client, qc, labels)
	err = qc.queryRange(func(_ int) error {
		s := models.DeviceSummaryItem{
			TrafficStats: &models.TrafficStats{
				RxBytes: optional.Uint64P(uint64(q.do(DeviceSummaryRxBytes))),
				TxBytes: optional.Uint64P(uint64(q.do(DeviceSummaryTxBytes))),
			},
		}
		list = append(list, s)
		return q.err
	})
	if err != nil {
		return nil, err
	}
	return
}
func max(n1, n2 int64) int64 {
	if n1 > n2 {
		return n1
	}
	return n2
}

func cmd(name, labels string) string {
	return fmt.Sprintf("%s{%s}", name, labels)
}
func rateCmd(name, labels string, timeRange int) string {
	return fmt.Sprintf("rate(%s{%s}[%dm])", name, labels, timeRange)
}

func (client *prometheusClient) DeviceRunTimeStats(namespace, userID, deviceID string, timeRange int) (*models.DeviceSummaryItem, error) {
	labels := map[string]string{
		"namespace": namespace,
		"user_id":   userID,
		"device_id": deviceID,
	}
	s := labelsToString(labels)
	return &models.DeviceSummaryItem{
		TrafficStats: &models.TrafficStats{
			RxBytes: optional.Uint64P(uint64(client.OneMetricQuery(cmd(DeviceSummaryRxBytes, s)))),
			TxBytes: optional.Uint64P(uint64(client.OneMetricQuery(cmd(DeviceSummaryTxBytes, s)))),
			RxSpeed: optional.Uint64P(uint64(max(client.OneMetricQuery(rateCmd(DeviceSummaryRxBytes, s, timeRange)), 0))),
			TxSpeed: optional.Uint64P(uint64(max(client.OneMetricQuery(rateCmd(DeviceSummaryTxBytes, s, timeRange)), 0))),
		},
	}, nil
}
func DeviceRunTimeStats(namespace, userID string, deviceID string, timeRange int) (*models.DeviceSummaryItem, error) {
	if prometheusInstance == nil {
		return nil, errNilPrometheusInstance
	}
	return prometheusInstance.DeviceRunTimeStats(namespace, userID, deviceID, timeRange)
}
func (client *prometheusClient) OneMetricQuery(cmd string) int64 {
	result, err := client.Query(cmd)
	if err != nil {
		return 0
	}
	val := result.(model.Vector)
	if len(val) == 0 {
		return 0
	}
	return int64(val[0].Value)
}
func DeviceSummaryStats(namespace, userID, deviceID string, day int) ([]models.DeviceSummaryItem, error) {
	if prometheusInstance == nil {
		return nil, errNilPrometheusInstance
	}
	qc := queryConditions{
		subRange:   1,
		timeUnit:   TimeUnitDay,
		totalRange: day,
		step:       1,
	}
	return prometheusInstance.DeviceSummaryStats(namespace, userID, deviceID, &qc)
}

func (client *prometheusClient) AggregationQuery(fn string, metric string, labels map[string]string, qc *queryConditions) (int64, error) {
	if !checkTimeUnit(qc.timeUnit) {
		return 0, fmt.Errorf("time unit invalid")
	}

	query := fmt.Sprintf("%s(%s{%s} [%d%c] ", fn, metric, labelsToString(labels), qc.subRange, qc.timeUnit)
	if qc.offset > 0 {
		query += fmt.Sprintf("offset %d%c", qc.offset, qc.timeUnit)
	}
	query += ")"
	result, err := client.Query(query)
	if err != nil {
		return 0, fmt.Errorf("query failed: %w %s", err, query)
	}
	val := result.(model.Vector)
	if len(val) == 0 {
		return 0, nil
	}

	return int64(val[0].Value), nil
}
func labelsToString(labels map[string]string) string {
	str := []string{}
	for k, v := range labels {
		str = append(str, fmt.Sprintf("%s=\"%s\"", k, v))
	}
	return strings.Join(str, ",")
}
func checkTimeUnit(u byte) bool {
	switch u {
	case TimeUnitMinutes, TimeUnitHour, TimeUnitDay, TimeUnitMonth:
		return true
	}
	return false
}
