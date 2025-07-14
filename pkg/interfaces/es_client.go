// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package interfaces

type EsStatsType int
const (
	EsDenyStats    EsStatsType = iota
	EsPermitStats
	EsAllStats
)
var (
	EsStatsTypeList = []EsStatsType{
		EsDenyStats,
		EsPermitStats,
		EsAllStats,
	}
)
func (t *EsStatsType) String() string {
	switch *t {
	case EsAllStats:    return "all"
	case EsPermitStats: return "permit"
	case EsDenyStats:   return "deny"
	}
	return "unknown"
}

type EsClientInterface interface {
	GetStatsForTopSrcIPs(string, int) ([]*EsStatsForSrcIP, error)
	GetStatsForTopDstIPs(string, int) ([]*EsStats, error)
	GetStatsForTopDomains(string, EsStatsType, int) ([]*EsStats, error)
}
