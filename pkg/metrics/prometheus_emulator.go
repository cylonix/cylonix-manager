package metrics

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/optional"
	"errors"
	"log"
	"math/rand"
	"time"

	"github.com/prometheus/common/model"
)

type PromEmulatorClient struct {
	userSummary   map[string]map[string]models.SummaryStatsList
	deviceSummary map[string]map[string]map[string][]models.DeviceSummaryItem
}

func NewPrometheusEmulator() (*PromEmulatorClient, error) {
	return &PromEmulatorClient{
		userSummary:   make(map[string]map[string][]models.SummaryStats),
		deviceSummary: make(map[string]map[string]map[string][]models.DeviceSummaryItem),
	}, nil
}

func (p *PromEmulatorClient) Query(query string) (model.Value, error) {
	return nil, errors.New("not implemented")
}
func (p *PromEmulatorClient) FirewallStats(namespace, srcID string) (*models.FirewallStats, error) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	maxRand := r.Int63()
	if maxRand < 1000000000 {
		maxRand = 1000000000
	}
	return &models.FirewallStats{
		AllowedRx:      optional.Uint64P(uint64(rand.Int63n(maxRand / 1000))),
		AllowedTx:      optional.Uint64P(uint64(rand.Int63n(maxRand / 1000))),
		DeniedRx:       optional.Uint64P(uint64(rand.Int63n(maxRand / 10000))),
		DeniedTx:       optional.Uint64P(uint64(rand.Int63n(maxRand / 10000))),
		DroppedRx:      optional.Uint64P(uint64(rand.Int63n(maxRand / 10000))),
		DroppedTx:      optional.Uint64P(uint64(rand.Int63n(maxRand / 10000))),
		AllowedRxBytes: optional.Uint64P(uint64(rand.Int63n(maxRand))),
		AllowedTxBytes: optional.Uint64P(uint64(rand.Int63n(maxRand))),
		DeniedRxBytes:  optional.Uint64P(uint64(rand.Int63n(maxRand / 10))),
		DeniedTxBytes:  optional.Uint64P(uint64(rand.Int63n(maxRand / 10))),
		DroppedRxBytes: optional.Uint64P(uint64(rand.Int63n(maxRand / 10))),
		DroppedTxBytes: optional.Uint64P(uint64(rand.Int63n(maxRand / 10))),
	}, nil
}
func (client *PromEmulatorClient) NamespaceSummaryStats(namespace string, qc *queryConditions) (models.SummaryStatsList, error) {
	return nil, nil
}
func (client *PromEmulatorClient) DeviceSummaryStats(namespace, userID, deviceID string, qc *queryConditions) ([]models.DeviceSummaryItem, error) {
	if _, ok := client.deviceSummary[namespace]; ok {
		if _, ok = client.deviceSummary[namespace][userID]; ok {
			return client.deviceSummary[namespace][userID][deviceID], nil
		}
	}
	return nil, nil
}
func (client *PromEmulatorClient) SetDeviceSummaryStats(namespace, userID, deviceID string, stats []models.DeviceSummaryItem) {
	if _, ok := client.deviceSummary[namespace]; !ok {
		client.deviceSummary[namespace] = make(map[string]map[string][]models.DeviceSummaryItem)
		if _, ok = client.deviceSummary[namespace][userID]; !ok {
			client.deviceSummary[namespace][userID] = make(map[string][]models.DeviceSummaryItem)
		}
	}
	client.deviceSummary[namespace][userID][deviceID] = stats
}
func (client *PromEmulatorClient) UserSummaryStats(namespace, userID string, qc *queryConditions) (models.SummaryStatsList, error) {
	log.Printf("PromEmulatorClient.UserSummaryStats: namespace=%s, userID=%s", namespace, userID)
	if n, ok := client.userSummary[namespace]; ok {
		return n[userID], nil
	}
	return nil, nil
}
func (client *PromEmulatorClient) SetUserSummaryStats(namespace, userID string, stats models.SummaryStatsList) {
	if _, ok := client.userSummary[namespace]; !ok {
		client.userSummary[namespace] = make(map[string][]models.SummaryStats)
	}
	log.Printf("PromEmulatorClient.SetUserSummaryStats: namespace=%s, userID=%s, stats=%#v", namespace, userID, stats)
	client.userSummary[namespace][userID] = stats
}
func (client *PromEmulatorClient) DeviceRunTimeStats(namespace, userID string, deviceID string, timeRange int) (*models.DeviceSummaryItem, error) {
	return nil, nil
}
func (client *PromEmulatorClient) OneMetricQuery(cmd string) int64 {
	return 0
}
func (client *PromEmulatorClient) AggregationQuery(fn string, metric string, labels map[string]string, qc *queryConditions) (int64, error) {
	return 0, nil
}
