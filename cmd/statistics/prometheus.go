package statistics

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/metrics"
	"cylonix/sase/pkg/optional"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	registry               *prometheus.Registry
	namespaceSummaryLabels = []string{"namespace"}
	userSummaryLabels      = []string{"namespace", "username", "user_id"}
	deviceSummaryLabels    = []string{"namespace", "username", "user_id", "device_name", "device_id"}
)

type PrometheusMetrics struct {
	namespaceSummary *namespaceSummary
	userSummary      *userSummary
	deviceSummary    *deviceSummary
}

type PrometheusMetricsInterface interface {
	PushDeviceSummary(namespace, username, userID, deviceName, deviceID string, stats *models.TrafficStats)
	PushUserSummary(namespace, username, userID string, m *models.SummaryStats)
	PushNamespaceSummary(namespace string, m *models.SummaryStats)
}

type PrometheusMetricsEmulator struct {
	namespaceSummary map[string][]*models.SummaryStats
	userSummary      map[string]map[string][]*models.SummaryStats
	deviceSummary    map[string]map[string]map[string][]*models.TrafficStats
}

func NewPrometheusMetricsEmulator() *PrometheusMetricsEmulator {
	return &PrometheusMetricsEmulator{
		namespaceSummary: make(map[string][]*models.SummaryStats),
		userSummary:      make(map[string]map[string][]*models.SummaryStats),
		deviceSummary:    make(map[string]map[string]map[string][]*models.TrafficStats),
	}
}

func (p *PrometheusMetricsEmulator) NamespaceSummary(namespace string) []*models.SummaryStats {
	return p.namespaceSummary[namespace]
}

func (p *PrometheusMetricsEmulator) UserSummary(namespace, userID string) []*models.SummaryStats {
	if n, ok := p.userSummary[namespace]; ok {
		return n[userID]
	}
	return nil
}

func (p *PrometheusMetricsEmulator) DeviceSummary(namespace, userID, deviceID string) []*models.TrafficStats {
	if n, ok := p.deviceSummary[namespace]; ok {
		if u, ok := n[userID]; ok {
			return u[deviceID]
		}
	}
	return nil
}

func (p *PrometheusMetricsEmulator) PushDeviceSummary(namespace, username, userID, deviceName, deviceID string, stats *models.TrafficStats) {
	if _, ok := p.deviceSummary[namespace]; !ok {
		p.deviceSummary[namespace] = make(map[string]map[string][]*models.TrafficStats)
	}
	if _, ok := p.deviceSummary[namespace][userID]; !ok {
		p.deviceSummary[namespace][userID] = make(map[string][]*models.TrafficStats)
	}
	v := p.deviceSummary[namespace][userID][deviceID]
	v = append(v, stats)
	p.deviceSummary[namespace][userID][deviceID] = v
}
func (p *PrometheusMetricsEmulator) PushUserSummary(namespace, username, userID string, m *models.SummaryStats) {
	if _, ok := p.userSummary[namespace]; !ok {
		p.userSummary[namespace] = make(map[string][]*models.SummaryStats)
	}
	v := p.userSummary[namespace][userID]
	v = append(v, m)
	p.userSummary[namespace][userID] = v
}
func (p *PrometheusMetricsEmulator) PushNamespaceSummary(namespace string, m *models.SummaryStats) {
	p.namespaceSummary[namespace] = append(p.namespaceSummary[namespace], m)
}

func (p *PrometheusMetrics) PushDeviceSummary(namespace, username, userID, deviceName, deviceID string, stats *models.TrafficStats) {
	p.deviceSummary.push(namespace, username, userID, deviceName, deviceID, stats)
}

func (p *PrometheusMetrics) PushUserSummary(namespace, username, userID string, m *models.SummaryStats) {
	p.userSummary.push(namespace, username, userID, m)
}

func (p *PrometheusMetrics) PushNamespaceSummary(namespace string, m *models.SummaryStats) {
	p.namespaceSummary.push(namespace, m)
}

type trafficStatsSummary struct {
	rxSpeed *prometheus.GaugeVec
	txSpeed *prometheus.GaugeVec
	rxBytes *prometheus.GaugeVec
	txBytes *prometheus.GaugeVec
}

type deviceSummary struct {
	trafficStatsSummary
}

type userSummary struct {
	onlineDeviceCount *prometheus.GaugeVec
	deviceCount       *prometheus.GaugeVec
	labelCount        *prometheus.GaugeVec
	policyCount       *prometheus.GaugeVec
	alarmCount        *prometheus.GaugeVec
	trafficStatsSummary
}

type namespaceSummary struct {
	userCount         *prometheus.GaugeVec
	onlineUserCount   *prometheus.GaugeVec
	deviceCount       *prometheus.GaugeVec
	onlineDeviceCount *prometheus.GaugeVec
	labelCount        *prometheus.GaugeVec
	policyCount       *prometheus.GaugeVec
	alarmCount        *prometheus.GaugeVec
	trafficStatsSummary
}

func (t *trafficStatsSummary) push(s *models.TrafficStats, lvs ...string) {
	if s == nil {
		return
	}
	if s.RxBytes != nil {
		t.rxBytes.WithLabelValues(lvs...).Set(float64(*s.RxBytes))
	}
	if s.TxBytes != nil {
		t.txBytes.WithLabelValues(lvs...).Set(float64(*s.TxBytes))
	}
	if s.RxSpeed != nil {
		t.rxSpeed.WithLabelValues(lvs...).Set(float64(*s.RxSpeed))
	}
	if s.TxSpeed != nil {
		t.txSpeed.WithLabelValues(lvs...).Set(float64(*s.TxSpeed))
	}
}

func (d *deviceSummary) push(namespace, username, userID, deviceName, deviceID string, s *models.TrafficStats) {
	d.trafficStatsSummary.push(s, namespace, username, userID, deviceName, deviceID)
}

func (u *userSummary) push(namespace, username, userID string, m *models.SummaryStats) {
	u.deviceCount.WithLabelValues(namespace, username, userID).Set(float64(optional.Int(m.DeviceCount)))
	u.labelCount.WithLabelValues(namespace, username, userID).Set(float64(optional.Int(m.LabelCount)))
	u.onlineDeviceCount.WithLabelValues(namespace, username, userID).Set(float64(optional.Int(m.OnlineDeviceCount)))
	u.alarmCount.WithLabelValues(namespace, username, userID).Set(float64(optional.Int(m.AlarmCount)))
	u.trafficStatsSummary.push(m.TrafficStats, namespace, username, userID)
}
func (n *namespaceSummary) push(namespace string, m *models.SummaryStats) {
	n.userCount.WithLabelValues(namespace).Set(float64(optional.Int(m.UserCount)))
	n.onlineUserCount.WithLabelValues(namespace).Set(float64(optional.Int(m.OnlineUserCount)))
	n.deviceCount.WithLabelValues(namespace).Set(float64(optional.Int(m.DeviceCount)))
	n.onlineDeviceCount.WithLabelValues(namespace).Set(float64(optional.Int(m.OnlineDeviceCount)))
	n.labelCount.WithLabelValues(namespace).Set(float64(optional.Int(m.LabelCount)))
	n.policyCount.WithLabelValues(namespace).Set(float64(optional.Int(m.PolicyCount)))
	n.alarmCount.WithLabelValues(namespace).Set(float64(optional.Int(m.AlarmCount)))
	n.trafficStatsSummary.push(m.TrafficStats, namespace)
}
func GetUserSummaryNameList() []string {
	return []string{
		metrics.UserSummaryDeviceCount,
		metrics.UserSummaryLabelCount,
		metrics.UserSummaryPolicyCount,
		metrics.UserSummaryRxBytes,
		metrics.UserSummaryTxBytes,
	}
}
func GetDeviceSummaryNameList() []string {
	return []string{
		metrics.DeviceSummaryRxBytes,
		metrics.DeviceSummaryTxBytes,
	}
}
func deviceSummaryInit() *deviceSummary {
	d := &deviceSummary{}
	d.rxBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: metrics.DeviceSummaryRxBytes,
			Help: "The rx bytes of the device",
		}, deviceSummaryLabels,
	)
	d.txBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: metrics.DeviceSummaryTxBytes,
			Help: "The tx bytes of the device",
		}, deviceSummaryLabels,
	)
	d.rxSpeed = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: metrics.DeviceSummaryRxSpeed,
			Help: "The device receiving traffic rate",
		}, deviceSummaryLabels,
	)
	d.txSpeed = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: metrics.DeviceSummaryTxSpeed,
			Help: "The device transmitting traffic rate",
		}, deviceSummaryLabels,
	)
	registry.MustRegister(d.rxBytes)
	registry.MustRegister(d.txBytes)
	registry.MustRegister(d.rxSpeed)
	registry.MustRegister(d.txSpeed)
	return d
}
func namespaceSummaryInit() *namespaceSummary {
	n := &namespaceSummary{
		userCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: metrics.NamespaceSummaryUserCount,
				Help: "The user number of namespace",
			},
			namespaceSummaryLabels,
		),
		alarmCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: metrics.NamespaceSummaryAlarmCount,
				Help: "The alarm number of namespace",
			},
			namespaceSummaryLabels,
		),
		onlineUserCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: metrics.NamespaceSummaryOnlineUserCount,
				Help: "The online user count of namespace",
			},
			namespaceSummaryLabels,
		),
		trafficStatsSummary: trafficStatsSummary{
			txSpeed: prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Name: metrics.NamespaceSummaryTxSpeed,
					Help: "The transmit rate of namespace",
				},
				namespaceSummaryLabels,
			),
			rxSpeed: prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Name: metrics.NamespaceSummaryRxSpeed,
					Help: "The receiving rate of namespace",
				},
				namespaceSummaryLabels,
			),
			rxBytes: prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Name: metrics.NamespaceSummaryRxBytes,
					Help: "The rx bytes of namespace",
				},
				namespaceSummaryLabels,
			),
			txBytes: prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Name: metrics.NamespaceSummaryTxBytes,
					Help: "The tx bytes of namespace",
				},
				namespaceSummaryLabels,
			),
		},
		labelCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: metrics.NamespaceSummaryLabelCount,
				Help: "The label number of namespace",
			},
			namespaceSummaryLabels,
		),
		policyCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: metrics.NamespaceSummaryPolicyCount,
				Help: "The policy number of namespace",
			},
			namespaceSummaryLabels,
		),
		deviceCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: metrics.NamespaceSummaryDeviceCount,
				Help: "The device number of namespace",
			},
			namespaceSummaryLabels,
		),
		onlineDeviceCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: metrics.NamespaceSummaryOnlineDeviceCount,
				Help: "The device number of namespace",
			},
			namespaceSummaryLabels,
		),
	}
	registry.MustRegister(n.userCount)
	registry.MustRegister(n.onlineUserCount)
	registry.MustRegister(n.labelCount)
	registry.MustRegister(n.policyCount)
	registry.MustRegister(n.deviceCount)
	registry.MustRegister(n.onlineDeviceCount)
	registry.MustRegister(n.alarmCount)
	registry.MustRegister(n.rxBytes)
	registry.MustRegister(n.txBytes)
	registry.MustRegister(n.rxSpeed)
	registry.MustRegister(n.txSpeed)
	return n
}
func prometheusUserSummaryInit() *userSummary {
	u := &userSummary{
		deviceCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: metrics.UserSummaryDeviceCount,
				Help: "The device count of user",
			},
			userSummaryLabels,
		),
		alarmCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: metrics.UserSummaryAlarmCount,
				Help: "The alarm count of user",
			},
			userSummaryLabels,
		),
		onlineDeviceCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: metrics.UserSummaryOnlineDeviceCount,
				Help: "The online device count of user",
			},
			userSummaryLabels,
		),
		labelCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: metrics.UserSummaryLabelCount,
				Help: "The number of labels of user",
			},
			userSummaryLabels,
		),
		policyCount: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: metrics.UserSummaryPolicyCount,
				Help: "The number of policies of user",
			},
			userSummaryLabels,
		),
		trafficStatsSummary: trafficStatsSummary{
			txSpeed: prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Name: metrics.UserSummaryTxSpeed,
					Help: "The tx speed of user",
				},
				userSummaryLabels,
			),
			rxSpeed: prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Name: metrics.UserSummaryRxSpeed,
					Help: "The online rx speed of user",
				},
				userSummaryLabels,
			),
			rxBytes: prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Name: metrics.UserSummaryRxBytes,
					Help: "The rx bytes of user",
				},
				userSummaryLabels,
			),
			txBytes: prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Name: metrics.UserSummaryTxBytes,
					Help: "The tx bytes of user",
				},
				userSummaryLabels,
			),
		},
	}
	registry.MustRegister(u.alarmCount)
	registry.MustRegister(u.deviceCount)
	registry.MustRegister(u.labelCount)
	registry.MustRegister(u.policyCount)
	registry.MustRegister(u.rxBytes)
	registry.MustRegister(u.txBytes)
	registry.MustRegister(u.onlineDeviceCount)
	registry.MustRegister(u.rxSpeed)
	registry.MustRegister(u.txSpeed)

	return u
}

func PrometheusServerInit() *PrometheusMetrics {
	registry = prometheus.NewPedanticRegistry()
	registry.MustRegister(collectors.NewProcessCollector(
		collectors.ProcessCollectorOpts{
			Namespace: metrics.AppNamespace,
		},
	))
	return &PrometheusMetrics{
		namespaceSummary: namespaceSummaryInit(),
		userSummary:      prometheusUserSummaryInit(),
		deviceSummary:    deviceSummaryInit(),
	}
}

func (*PrometheusMetrics) Run() {
	go func() {
		http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		log.Fatal(http.ListenAndServe(":9001", nil))
	}()
}
