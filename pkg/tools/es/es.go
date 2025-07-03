package es

import (
	"bytes"
	"context"
	"cylonix/sase/pkg/interfaces"
	"cylonix/sase/pkg/logging/logfields"
	"encoding/json"
	"errors"

	"github.com/cylonix/utils"
	ulog "github.com/cylonix/utils/log"
	"github.com/sirupsen/logrus"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

var (
	QUERY_RESP_ERR = "query response is an error: "
)

type EsClient struct {
	config *elasticsearch.Config
	logger *logrus.Entry
}

type esQuery struct {
	es        *EsClient
	namespace string
	query     map[string]interface{}
}

func (es *EsClient) newEsQuery(namespace string, query map[string]interface{}) *esQuery {
	return &esQuery{
		es:        es,
		query:     query,
		namespace: namespace,
	}
}

func NewEsClient(esURL string, logger *logrus.Entry) (*EsClient, error) {
	if esURL == "" {
		return nil, errors.New("invalid elastic search url")
	}
	cfg := &elasticsearch.Config{
		Addresses: []string{
			esURL,
		},
	}
	return &EsClient{
		config: cfg,
		logger: logger.WithField(logfields.LogSubsys, "ES"),
	}, nil
}

func (es *EsClient) search(namespace string, query map[string]interface{}) (*esapi.Response, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, err
	}

	client, err := elasticsearch.NewClient(*es.config)
	if err != nil {
		return nil, err
	}

	res, err := client.Search(
		client.Search.WithContext(context.Background()),
		client.Search.WithIndex(utils.GetEsNamespaceIndex(namespace)),
		//client.Search.WithIndex("sase-flow"),
		client.Search.WithBody(&buf),
		client.Search.WithTrackTotalHits(true),
		client.Search.WithPretty(),
	)

	return res, err
}

func (q *esQuery) search() (*interfaces.EsAggrResponse, error) {
	res, err := q.es.search(q.namespace, q.query)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.IsError() {
		return nil, errors.New(QUERY_RESP_ERR + res.String())
	}
	response := interfaces.EsAggrResponse{}
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (es *EsClient) getAggsQueryWithFilter(namespace, field, filterField, filterVal string, size, shardSize int) *esQuery {
	mustList := make([]map[string]interface{}, 0)
	item := map[string]interface{}{
		"term": map[string]interface{}{
			filterField: filterVal,
		},
	}
	mustList = append(mustList, item)
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": map[string]interface{}{
					"exists": map[string]interface{}{
						"field": "destination_names",
					},
				},
				"filter": map[string]interface{}{
					"bool": map[string]interface{}{
						"must": mustList,
					},
				},
			},
		},
		"aggs": map[string]interface{}{
			"age_terms": map[string]interface{}{
				"terms": map[string]interface{}{
					"field":                     field,
					"size":                      size,
					"shard_size":                shardSize,
					"show_term_doc_count_error": true,
				},
			},
		},
	}

	return es.newEsQuery(namespace, query)
}

func (es *EsClient) getAggsQuery(namespace, field string, size, shardSize int) *esQuery {
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"exists": map[string]interface{}{
				"field": "destination_names",
			},
		},
		"aggs": map[string]interface{}{
			"age_terms": map[string]interface{}{
				"terms": map[string]interface{}{
					"field":                     field,
					"size":                      size,
					"shard_size":                shardSize,
					"show_term_doc_count_error": true,
				},
			},
		},
	}

	return es.newEsQuery(namespace, query)
}

func (es *EsClient) getMustMatchQuery(namespace, matchField, matchVal, resultField string, size, shardSize int) *esQuery {
	mustList := make([]map[string]interface{}, 0)
	item := map[string]interface{}{"term": map[string]interface{}{matchField: matchVal}}
	mustList = append(mustList, item)
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": map[string]interface{}{
					"match_all": map[string]interface{}{},
				},
				"filter": map[string]interface{}{
					"bool": map[string]interface{}{
						"must": mustList,
					},
				},
			},
		},
		"aggs": map[string]interface{}{
			"age_terms": map[string]interface{}{
				"terms": map[string]interface{}{
					"field":                     resultField,
					"size":                      size,
					"shard_size":                shardSize,
					"show_term_doc_count_error": true,
				},
			},
		},
	}
	return es.newEsQuery(namespace, query)
}

// GetStatsForTopSrcIP returns the access stats for top users based on
// the source IP.
func (es *EsClient) GetStatsForTopSrcIPs(namespace string, top int) ([]*interfaces.EsStatsForSrcIP, error) {
	log := es.logger.WithField(ulog.Namespace, namespace).WithField(ulog.Handle, "get top app per source")

	// Fetch the top source IPs
	shard := int(utils.ElasticSearchShardRatio * top)
	response, err := es.getAggsQuery(namespace, "IP.source", top, shard).search()
	if err != nil {
		log.WithError(err).Debugln("query error")
		return nil, err
	}

	// For each source IP, fetch the destinations.
	var statList []*interfaces.EsStatsForSrcIP
	log.WithField("src-ip-num", len(response.Aggregations.Terms.Buckets)).Debugln("buckets")
	for _, val := range response.Aggregations.Terms.Buckets {
		ip := val.Key
		_log := log.WithField("ip", ip)
		_log.Debugln("getting the stats")
		stats, err := es.GetElasticsearchWithIp(namespace, ip)
		if err != nil {
			_log.WithError(err).Warnln("failed to query with this source ip.")
			continue
		}
		statList = append(statList, &interfaces.EsStatsForSrcIP{
			SrcIP: ip,
			Stats: stats,
		})
	}
	log.WithField("size", len(statList)).Debugln("top source IPs' app list success")
	return statList, nil
}

func (es *EsClient) GetElasticsearchWithIp(namespace, ip string) ([]*interfaces.EsStats, error) {
	log := es.logger.WithField(ulog.Namespace, namespace).WithField("ip", ip)

	top := utils.MaxElasticSearchAggrTop
	shard := int(utils.ElasticSearchShardRatio * top)
	query := es.getMustMatchQuery(namespace, "IP.source", ip, "destination_names", top, shard)
	response, err := query.search()
	if err != nil {
		log.WithError(err).Debugln("query error")
		return nil, err
	}

	var IPStatus []*interfaces.EsStats
	for _, val := range response.Aggregations.Terms.Buckets {
		item := &interfaces.EsStats{
			DstIP:  val.Key,
			Count:  val.Count,
			Domain: val.Key,
		}
		IPStatus = append(IPStatus, item)
		// log.WithField("stats", *item).Debugln("get source ip stats success")
	}

	return IPStatus, nil
}

func (es *EsClient) GetStatsForTopDstIPs(namespace string, top int) ([]*interfaces.EsStats, error) {
	log := es.logger.WithField(ulog.Namespace, namespace).WithField(ulog.Handle, "get top dest ip")
	shard := int(utils.ElasticSearchShardRatio * top)
	query := es.getAggsQuery(namespace, "IP.destination", top, shard)
	response, err := query.search()
	if err != nil {
		log.WithError(err).Debugln("query failed")
		return nil, err
	}
	var ret []*interfaces.EsStats
	for _, val := range response.Aggregations.Terms.Buckets {
		item := &interfaces.EsStats{
			DstIP: val.Key,
			Count: val.Count,
		}
		ret = append(ret, item)
	}
	log.WithField("size", len(ret)).Debugln("success")
	return ret, nil
}

// GetStatsForTopDomains gets the top destinations
func (es *EsClient) GetStatsForTopDomains(namespace string, statsType interfaces.EsStatsType, top int) ([]*interfaces.EsStats, error) {
	log := es.logger.WithField(ulog.Namespace, namespace).WithField(ulog.Handle, "get top dest domains")
	shard := int(utils.ElasticSearchShardRatio * top)
	query := es.getAggsQuery(namespace, "destination_names", top, shard)

	switch statsType {
	case interfaces.EsAllStats: // No-op
	case interfaces.EsPermitStats:
		query = es.getAggsQueryWithFilter(namespace, "destination_names",
			"verdict", "FORWARDED", top, shard)
	case interfaces.EsDenyStats:
		query = es.getAggsQueryWithFilter(namespace, "destination_names",
			"verdict", "DROPPED", top, shard)
	default:
		err := errors.New("unknown stats type")
		log.WithError(err).Errorln("unsupported query")
		return nil, err
	}

	log = log.WithField("type", statsType.String())
	response, err := query.search()
	var queryStr bytes.Buffer
	json.NewEncoder(&queryStr).Encode(query.query)
	if err != nil {
		log.WithError(err).WithField("cmd", queryStr.String()).Debugln("query failed")
		return nil, err
	}

	var ret []*interfaces.EsStats
	for _, val := range response.Aggregations.Terms.Buckets {
		item := &interfaces.EsStats{
			Domain: val.Key,
			Count:  val.Count,
		}
		ret = append(ret, item)
	}
	log.WithField("size", len(ret)).Debugln("success")
	return ret, nil
}
