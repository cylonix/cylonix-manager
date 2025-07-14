// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package interfaces

type EsStatsForSrcIP struct {
	SrcIP string
	Stats []*EsStats
}

type EsStats struct {
	Count  int
	DstIP  string
	Domain string
}

type EsAggrBucket struct {
	Count int    `json:"doc_count"`
	Key   string `json:"key"`
}

type EsAggrTerms struct {
	Sum     int            `json:"sum_other_doc_count"`
	Buckets []EsAggrBucket `json:"buckets"`
}

type EsAggregations struct {
	Terms EsAggrTerms `json:"age_terms"`
}

type EsAggrResponse struct {
	Took         int            `json:"took"`
	Aggregations EsAggregations `josn:"aggregations"`
}
