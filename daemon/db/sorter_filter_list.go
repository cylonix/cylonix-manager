// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"strings"

	"github.com/cylonix/utils/etcd"
	"github.com/cylonix/utils/paging"
	"go.etcd.io/etcd/api/v3/mvccpb"
)

type SortableFilterableListInterface interface {
	Data(value []byte) interface{}
	Filter(data interface{}, filterBy, filterValue *string) bool
	Key(id string) string
	Swap(d1, d2 interface{}, sortBy string, sortDesc bool) bool
}

type SortableFilterableList struct {
	i SortableFilterableListInterface
}

func (s *SortableFilterableList) List(
	contain, filterBy, filterValue, sortBy, sortDesc *string,
	idList []string, page, pageSize *int,
) (int, []interface{}, error) {
	var kvList []*mvccpb.KeyValue
	if len(idList) > 0 {
		for _, id := range idList {
			path := s.i.Key(id)
			resp, err := etcd.GetWithKey(path)
			if err == nil {
				kvList = append(kvList, resp.Kvs...)
			}
		}
	} else {
		resp, err := etcd.GetWithPrefix(s.i.Key(""))
		if err != nil {
			return 0, nil, err
		}
		kvList = resp.Kvs
	}
	var list []interface{}
	for _, kv := range kvList {
		if contain != nil && *contain != "" {
			if !strings.Contains(string(kv.Value), *contain) {
				continue
			}
		}
		data := s.i.Data(kv.Value)
		if data == nil {
			continue
		}
		filterBy = camelToSnake(filterBy)
		if s.i.Filter(data, filterBy, filterValue) {
			continue
		}
		list = append(list, data)
	}
	sorted := s.Sort(sortBy, sortDesc, list)
	total := len(sorted)
	if page == nil || *page < 0 || pageSize == nil || *pageSize <= 0 {
		return total, list, nil
	}
	start, stop := paging.StartStop(page, pageSize, total)
	return total, sorted[start:stop], nil
}

func (s *SortableFilterableList) Sort(sortBy, sortDesc *string, list []interface{}) []interface{} {
	if sortBy == nil || *sortBy == "" {
		return list
	}
	desc := false
	if sortDesc != nil && *sortDesc == "desc" {
		desc = true
	}

	var n = len(list)
	sortBy = camelToSnake(sortBy)
	for i := 0; i <= n-1; i++ {
		for j := i; j <= n-1; j++ {
			if s.i.Swap(list[i], list[j], *sortBy, desc) {
				t := list[i]
				list[i] = list[j]
				list[j] = t
			}
		}
	}
	return list
}
