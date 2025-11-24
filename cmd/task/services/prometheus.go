// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package services

import (
	"context"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/cmd/clients"
	"cylonix/sase/cmd/statistics"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"errors"
	"fmt"
	"time"

	"github.com/cylonix/wg_agent"

	ulog "github.com/cylonix/utils/log"
	"github.com/cylonix/utils/postgres"

	"github.com/sirupsen/logrus"
)

const (
	dash = "======================="
	defaultPrometheusTaskInterval = 60 // seconds
)

type PrometheusTaskInstance struct {
	prometheus     statistics.PrometheusMetricsInterface
	name           string
	logger         *logrus.Entry
	ts             *TaskTable
	wgNamespaceMap map[string]string
	wgClientList   []*clients.WgState
}

type trafficStats struct {
	userID            types.UserID
	username          string
	deviceName        string
	lastSeen          int64
	onlineDeviceCount int
	types.TrafficStats
}

type namespaceTask struct {
	p             *PrometheusTaskInstance
	namespace     string
	logger        *logrus.Entry
	errLogged     bool
	deviceMap     map[types.DeviceID]*trafficStats
	userMap       map[types.UserID]*trafficStats
	labelCountMap map[types.UserID]int64
	summary       models.SummaryStats
	trafficStats  types.TrafficStats
}

func NewPrometheusTaskInstance(ts *TaskTable, prometheus statistics.PrometheusMetricsInterface) *PrometheusTaskInstance {
	return &PrometheusTaskInstance{
		ts:         ts,
		prometheus: prometheus,
		name:       "Prometheus task instance",
		logger:     ts.Logger.WithField("task", "prometheus-task"),
	}
}

func (p *PrometheusTaskInstance) Interval() int {
	interval := p.ts.Config.Interval
	if interval <= 0 {
		return defaultPrometheusTaskInterval
	}
	return interval
}

func (p *PrometheusTaskInstance) Name() string {
	return p.name
}

func (p *PrometheusTaskInstance) newNamespaceTask(namespace string) *namespaceTask {
	return &namespaceTask{
		p:         p,
		namespace: namespace,
		logger:    p.logger.WithField(ulog.Namespace, namespace),
		deviceMap: make(map[types.DeviceID]*trafficStats),
		userMap:   make(map[types.UserID]*trafficStats),
	}
}

func (p *PrometheusTaskInstance) Task(initData bool) {
	p.logger.Infoln(dash, "Prometheus metrics task", dash)
	s, err := wgClientList()
	if err != nil {
		p.logger.WithError(err).Errorln("Failed to get current wg client map.")
	}
	p.wgClientList = s
	p.wgNamespaceMap = wgNamespaceMap()
	for _, namespace := range p.ts.NamespaceList() {
		n := p.newNamespaceTask(namespace)
		go func() {
			p.logger.Infoln(dash, namespace, "Prometheus Task BEGIN", dash)
			n.doTask()
			p.logger.Infoln(dash, namespace, "Prometheus Task END", dash)
		}()
	}
}

// Full scan push all users and devices from db if no update is available.
// This is useful when the task first starts to initialize data to serve
// prometheus queries.
// Update scan only push those that have updates.
func (n *namespaceTask) doTask() {
	n.collectDeviceTraffic()
	n.setupUserMap()
	n.collectNamespaceCounters()
	n.scanUsers()

	// Push namespace summary.
	ns := &n.summary
	now := time.Now().Unix()
	ts := n.trafficStats.ToModel()
	ns.Timestamp = &now
	ns.TrafficStats = ts
	if err := db.CreateOrUpdateNamespaceSummaryStat(n.namespace, ns); err != nil {
		n.logger.WithError(err).Errorln("Failed to update namespace summary to db.")
	}
	n.p.prometheus.PushNamespaceSummary(n.namespace, ns)
}

func (n *namespaceTask) collectNamespaceCounters() {
	logger := n.logger
	namespace := n.namespace
	logger.Debugln("Start collecting namespace counters.")

	labelCountMap, err := db.LabelCountUserIDMap()
	if err != nil {
		logger.WithError(err).Errorln("Failed to get user label count from db.")
	} else {
		n.labelCountMap = labelCountMap
	}
	labelCount, err := n.labelCount()
	if err != nil {
		logger.WithError(err).Errorln("Failed to get label count.")
	} else {
		n.summary.LabelCount = &labelCount
	}
	userCount, err := db.UserCount(&namespace, nil, false)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get user count from db.")
	} else {
		cnt := int(userCount)
		n.summary.UserCount = &cnt
	}
	policyCount, err := db.PolicyCount(namespace)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get policy count from db.")
	} else {
		cnt := int(policyCount)
		n.summary.PolicyCount = &cnt
	}
}

// FullScan will initialize the data from db if there is no update available.
func (n *namespaceTask) scanUsers() {
	n.logger.Debugln("Start processing users in batch.")
	err := db.FindUserInBatches(n.namespace, 100, func(user *types.User) (bool, error) {
		n.collectAndPushUserAndDevices(user.ID)
		return false, nil
	})

	if err != nil {
		n.logger.WithError(err).Errorln("Failed to process user in batches.")
		return
	}
}

func (n *namespaceTask) setupUserMap() {
	namespace := n.namespace
	logger := n.logger
	n.errLogged = false
	ns := &n.summary
	nt := &n.trafficStats
	online := 0
	for deviceID, v := range n.deviceMap {
		log := logger.WithField(ulog.DeviceID, deviceID)
		// Get the username, userID, device name, device ID.
		device := &types.Device{}
		if err := db.GetUserDevice(namespace, deviceID, device); err != nil {
			n.logOnce(log, err, "Failed to get device from db.")
			continue
		}
		userID := device.UserID
		user, err := db.GetUserFast(namespace, userID, false)
		if err != nil {
			n.logOnce(log, err, "Failed to get user from database")
			continue
		}

		// So that we can push the stats without looking this up again.
		v.userID = userID
		v.username = user.UserBaseInfo.DisplayName
		v.deviceName = device.NameAlias

		// Roll up device stats to the user and namespace.
		vt := &v.TrafficStats
		s, ok := n.userMap[userID]
		if !ok {
			stats := *v
			s = &stats
			n.userMap[userID] = s
		} else {
			st := &s.TrafficStats
			st.Add(vt)
		}

		if common.IsLastSeenOnline(v.lastSeen) {
			online += 1
			s.onlineDeviceCount += 1
		}
		if s.lastSeen < v.lastSeen {
			s.lastSeen = v.lastSeen
		}
		nt.Add(vt) // Namespace traffic stats.
	}
	ns.OnlineDeviceCount = optional.AddIntP(ns.OnlineDeviceCount, online)
}

func (n *namespaceTask) collectWgStats() (list []wg_agent.WgUserStats, err error) {
	logger := n.logger.WithField(ulog.Handle, "collect-wg-stats")
	namespace := n.namespace
	namespaceWg, ok := n.p.wgNamespaceMap[namespace]
	if !ok {
		if len(n.p.ts.Config.WgConfig) <= 0 {
			return nil, nil
		}
		logger.Warnln("Failed to find wg namespace mapping.")
		return nil, fmt.Errorf("get wg namespace map failed ")
	}
	logger = logger.WithField("namespace-wg", namespaceWg)
	for _, c := range n.p.wgClientList {
		if c.Offline {
			continue
		}
		log := logger.WithField("wg", c.Name)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req := c.Client.NamespaceAPI.GetNamespaceAllUserStats(ctx)
		req = req.WgNamespace(*wg_agent.NewWgNamespace(namespaceWg))
		s, resp, err := c.Client.NamespaceAPI.GetNamespaceAllUserStatsExecute(req)
		if err != nil || resp == nil {
			c.Offline = true
			log.WithError(err).Warnln("Failed to get stats from wg.")
			continue
		}
		for i := range s {
			s[i].Name = c.Name // Record the wg-server-name in the stats.
		}
		if len(s) > 0 {
			list = append(list, s...)
		}
	}
	return
}

func (n *namespaceTask) collectDeviceTraffic() {
	namespace := n.namespace
	logger := n.logger
	deviceMap := n.deviceMap
	list, err := n.collectWgStats()
	if err != nil {
		logger.WithError(err).Errorln("Failed to get namespace wg stats.")
		return
	}
	n.errLogged = false
	for _, s := range list {
		id, err := types.ParseID(s.DeviceID)
		if err != nil {
			n.logOnce(logger, err, "Failed to decode device ID to uuid")
			continue
		}
		deviceID := id
		log := logger.WithField(ulog.DeviceID, deviceID)
		d, err := db.UpdateDeviceTrafficByWgData(namespace, deviceID, s.LastHandshakeTime, uint64(s.RxBytes), uint64(s.TxBytes), s.Name)
		if err != nil {
			n.logOnce(log, err, "Failed to update device traffic stats in db.")
			continue
		}
		t := &d.TrafficStats
		v, ok := deviceMap[deviceID]
		if !ok {
			deviceMap[deviceID] = &trafficStats{
				lastSeen:     s.LastHandshakeTime,
				TrafficStats: *t,
			}
			v = deviceMap[deviceID]
		}
		if v.lastSeen < s.LastHandshakeTime {
			v.lastSeen = s.LastHandshakeTime
		}
		vt := &v.TrafficStats
		vt.Add(t)
	}
}

// Collect user traffic gets the summary of the user either from the db
// or from the updated devices. It also pushes the device summary from
// db if there is no update available.
func (n *namespaceTask) collectAndPushUserAndDevices(userID types.UserID) {
	namespace := n.namespace
	logger := n.logger.WithField(ulog.UserID, userID)
	logger.Debugln("Start collecting user and devices summary")
	su, err := db.GetUserFast(namespace, userID, false)
	if err != nil {
		n.logOnce(logger, err, "Failed to get user from db.")
		return
	}
	devices, err := db.GetUserDeviceListFast(namespace, userID)
	if err != nil {
		if !errors.Is(err, db.ErrDeviceNotExists) {
			n.logOnce(logger, err, "Failed to get user devices from db.")
			return
		}
	}

	// Push device summary for all devices of the user.
	n.errLogged = false
	username := su.UserBaseInfo.DisplayName
	for _, device := range devices {
		deviceID := device.ID
		deviceName := device.NameAlias
		log := logger.WithField(ulog.DeviceID, deviceID)
		var ts *models.TrafficStats
		if v, ok := n.deviceMap[deviceID]; ok {
			ts, err = v.TrafficStats.ToModel(), n.updateDeviceStats(deviceID, v)
		} else {
			ts, err = db.DeviceAggregateTrafficStats(namespace, deviceID)
		}
		if err == nil {
			n.p.prometheus.PushDeviceSummary(n.namespace, username, userID.String(), deviceName, deviceID.String(), ts)
		} else {
			n.logOnce(log, err, "Failed to push device summary")
		}
	}

	// Push user summary from DB or from updated stats.
	ns := &n.summary
	ns.DeviceCount = optional.AddIntP(ns.DeviceCount, len(devices))

	var s *models.SummaryStats
	var v *trafficStats
	var ok bool
	if v, ok = n.userMap[userID]; ok {
		if common.IsLastSeenOnline(v.lastSeen) {
			ns.OnlineUserCount = optional.AddIntP(ns.OnlineUserCount, 1)
		}
	} else {
		if s, err = db.LastUserSummaryStat(userID); err == nil {
			v = &trafficStats{
				userID: userID,
				onlineDeviceCount: optional.Int(s.OnlineDeviceCount),
				TrafficStats: types.NewTrafficStats(s.TrafficStats),
			}
		} else {
			n.logOnce(logger, err, "Failed to get last summary from db.")
		}
	}
	if err == nil {
		s, err = n.updateUserSummary(len(devices), v)
		if err != nil {
			n.logOnce(logger, err, "Failed to update user summary.")
			return
		}
		ns.AlarmCount = optional.AddIntP(ns.AlarmCount, optional.Int(s.AlarmCount))
		ns.AlarmUnread = optional.AddIntP(ns.AlarmUnread, optional.Int(s.AlarmUnread))
		n.p.prometheus.PushUserSummary(namespace, username, userID.String(), s)
	}
}

func (n *namespaceTask) updateDeviceStats(deviceID types.DeviceID, v *trafficStats) error {
	update := &types.WgInfo{
		LastSeen: v.lastSeen,
		RxBytes:  optional.Uint64(v.RxBytes),
		TxBytes:  optional.Uint64(v.TxBytes),
	}
	if err := db.UpdateWgInfo(nil, deviceID, update); err != nil {
		return fmt.Errorf("failed to update wg info: %w", err)
	}
	return nil
}

func (n *namespaceTask) updateUserSummary(deviceCount int, v *trafficStats) (*models.SummaryStats, error) {
	vt := &v.TrafficStats
	now, ts := time.Now().Unix(), vt.ToModel()
	us := &models.SummaryStats{
		DeviceCount:       &deviceCount,
		Timestamp:         &now,
		OnlineDeviceCount: &v.onlineDeviceCount,
		TrafficStats:      ts,
	}
	namespace := n.namespace

	// Alarm count.
	read, unread, err := db.AlarmCount(namespace, v.userID)
	if err != nil {
		err = fmt.Errorf("failed to get alarm count from db: %w", err)
	} else {
		cnt := int(read + unread)
		unreadCnt := int(unread)
		us.AlarmCount = &cnt
		us.AlarmUnread = &unreadCnt
	}

	// Label count.
	if labelCount, ok := n.labelCountMap[v.userID]; ok {
		cnt := int(labelCount)
		us.LabelCount = &cnt
	}

	// Save to DB.
	if newErr := db.CreateOrUpdateUserSummaryStat(namespace, v.userID, us); newErr != nil {
		err = errors.Join(err, fmt.Errorf("failed to update user summary in db: %w", newErr))
	}
	return us, err
}

func (n *namespaceTask) labelCount() (int, error) {
	namespace := n.namespace
	label := types.Label{
		Namespace: namespace,
	}
	cnt, err := postgres.TableCount(&label, label)
	return int(cnt), err
}

func (n *namespaceTask) logOnce(logger *logrus.Entry, err error, msg string) {
	if !n.errLogged {
		logger.WithError(err).Errorln(msg)
		n.errLogged = true
	}
}
