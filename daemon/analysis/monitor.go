// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package analysis

import (
	"bytes"
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/cylonix/utils"
	ulog "github.com/cylonix/utils/log"
	"github.com/cylonix/utils/paging"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/sirupsen/logrus"
)

type monitorHandlerImpl struct {
	logger *logrus.Entry
}

func newMonitorHandlerImpl(logger *logrus.Entry) *monitorHandlerImpl {
	return &monitorHandlerImpl{
		logger: logger,
	}
}

func esClient() (*elasticsearch.Client, error) {
	url := utils.GetElasticsearchURL()
	cfg := elasticsearch.Config{
		Addresses: []string{
			url,
		},
	}
	return elasticsearch.NewClient(cfg)
}

func (h *monitorHandlerImpl) appendFilter(
	mustList *[]map[string]interface{},
	key string,
	val interface{},
) {
	switch v := val.(type) {
	case string:
		if v == "" {
			return
		}
	case int64:
		if v == 0 {
			return
		}
	default:
		// Not expected.
		h.logger.WithFields(logrus.Fields{
			ulog.SubHandle: "append-filter",
			ulog.Key:       key,
			"value-type":   v,
		}).Warnln("Unexpected value type.")
		return
	}
	item := map[string]interface{}{
		"term": map[string]interface{}{key: val},
	}
	*mustList = append(*mustList, item)
}

func (h *monitorHandlerImpl) setFilter(
	filter *models.MonitorFlowFilter,
	mustList *[]map[string]interface{},
) {
	h.appendFilter(mustList, "Type", filter.Type)
	h.appendFilter(mustList, "l7.L7_Type.keyword", filter.L7Type)
	h.appendFilter(mustList, "verdict", filter.Verdict)
	h.appendFilter(mustList, "IP.source", filter.SrcIP)
	h.appendFilter(mustList, "IP.destination", filter.DstIP)
	h.appendFilter(mustList, "source.labels", filter.SrcLabel)
	h.appendFilter(mustList, "destination.labels", filter.DstLabel)
	h.appendFilter(mustList, "source.identity", filter.SrcIdentity)
	h.appendFilter(mustList, "destination.identity", filter.DstIdentity)
	h.appendFilter(mustList, "l4.udp.source_port", filter.SrcUDPPort)
	h.appendFilter(mustList, "l4.udp.destination_port", filter.DstUDPPort)
	h.appendFilter(mustList, "l4.tcp.source_port", filter.SrcTCPPort)
	h.appendFilter(mustList, "l4.tcp.destination_port", filter.DstTCPPort)
}

/*
 * Example:
 *
 *	{"query":{
 *		"bool": {
 *			"must": {"match_all": {}},
 *			"filter": {
 *				"bool" : {
 *					"must" : [
 *						{"term" : { "IP.source":"192.168.88.3" } },
 *						{"term" : { "source.labels" : "reserved:world" } }
 *					]
 *				}
 *			}
 *		}
 *	}}
 */
func (h *monitorHandlerImpl) elasticsearchQueryString(
	size, from int, filter *models.MonitorFlowFilter,
) *map[string]interface{} {
	mustList := make([]map[string]interface{}, 0)

	// We can only search the record in passed 24 hours
	item := map[string]interface{}{
		"range": map[string]interface{}{
			"time": map[string]interface{}{
				"gte": "now-1d/d",
			},
		},
	}
	mustList = append(mustList, item)

	if filter != nil {
		h.setFilter(filter, &mustList)
	}
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": mustList,
			},
		},
		"size": size,
		"from": from,
		// Sort by insert time
		"sort": map[string]interface{}{
			"time": map[string]interface{}{
				"order": "desc",
			},
		},
	}

	return &query
}

func (h *monitorHandlerImpl) ListFlow(auth interface{}, requestObject api.ListMonitorFlowRequestObject) (*models.MonitorFlowList, error) {
	token, namespace, _, logger := common.ParseToken(auth, "list-flow", "List flow", h.logger)
	// Only support listing from admin user for now.
	if !token.IsAdminUser {
		logger.Warnln("Non-admin user listing monitor flows.")
		return nil, common.ErrModelUnauthorized
	}
	params := requestObject.Params
	client, err := esClient()
	if err != nil {
		logger.WithError(err).Errorln("Failed to get elastic search client.")
		return nil, common.ErrInternalErr
	}
	max := utils.MaxElasticSearchOffset
	start, stop := paging.StartStop(params.Page, params.PageSize, max)

	// Return a empty list when it is beyond the offset scope.
	if (start + stop) > utils.MaxElasticSearchOffset {
		logger.WithField("from", start).Warnln("ES offset is beyond the scope.")
		return &models.MonitorFlowList{
			Total: utils.MaxElasticSearchOffset,
			Items: nil,
		}, nil
	}

	var buf bytes.Buffer
	query := h.elasticsearchQueryString(stop-start, start, requestObject.Body)
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		logger.WithError(err).Errorln("Failed to encode query.")
		return nil, common.ErrInternalErr
	}

	indexName := "sase-flow-" + namespace
	// Perform the search request.
	res, err := client.Search(
		client.Search.WithContext(context.Background()),
		client.Search.WithIndex(indexName),
		client.Search.WithBody(&buf),
		client.Search.WithTrackTotalHits(true),
		client.Search.WithPretty(),
	)
	if err != nil {
		logger.WithError(err).Errorln("Failed to search.")
		return nil, common.ErrInternalErr
	}
	defer res.Body.Close()

	if res.IsError() {
		logger.WithError(nil).Errorln("Failed to search.")
		return nil, common.ErrInternalErr
	}

	var mapResp map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&mapResp); err != nil {
		logger.WithError(err).Errorln("Failed to parse the response body.")
		return nil, common.ErrInternalErr
	}
	hits := mapResp["hits"].(map[string]interface{})
	total := hits["total"].(map[string]interface{})
	totalNum, err := strconv.ParseInt(fmt.Sprintf("%v", total["value"]), 10, 64)
	if err != nil {
		logger.WithError(err).Errorln("Failed to parse the total value.")
		return nil, common.ErrInternalErr
	}
	docs := hits["hits"].([]interface{})
	var docArray []string
	for _, doc := range docs {
		b, err := json.Marshal(doc)
		if err != nil {
			logger.WithError(err).Warnln("Error in parsing json")
			continue
		}
		// TODO: what the hack!?
		if strings.Contains(string(b), "172.19.60") {
			continue
		}
		docArray = append(docArray, string(b))
	}

	// Limit the max offset in ES
	if totalNum > utils.MaxElasticSearchOffset {
		totalNum = utils.MaxElasticSearchOffset
	}
	return &models.MonitorFlowList{
		Total: int(totalNum),
		Items: &docArray,
	}, nil
}
