// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"fmt"
	"net/netip"
	"strings"

	"gorm.io/gorm"
)

// Since drop table does not drop many to many relationship table, we need to
// do this explicitly by using a drop interface.
type DropManyToManyTables interface {
	DropManyToMany(db *gorm.DB) error
}

func dropManyToMany(db *gorm.DB, tables ...interface{}) error {
	if err := db.Migrator().DropTable(tables...); err != nil {
		return fmt.Errorf("failed to drop %v: %w", tables, err)
	}
	return nil
}

func shortStringN(str string, n int) string {
	if len(str) > n {
		str = str[:n]
	}
	return "[" + str + "]"
}

type ValidString interface {
	IsValid() bool
	String() string
}

func ToStringSlice[T ValidString](list []T) []string {
	s := make([]string, 0, len(list))
	for _, v := range list {
		if v.IsValid() {
			s = append(s, v.String())
		}
	}
	return s
}
func FromStringSlice[T any](ss []string, parseFn func(string) (T, error)) ([]T, error) {
	var list []T
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := parseFn(s)
		if err != nil {
			return nil, fmt.Errorf("failed to parse '%v': %w", s, err)
		}
		list = append(list, p)
	}
	return list, nil
}
func ParsePrefixes(ss []string) ([]netip.Prefix, error) {
	return FromStringSlice(ss, netip.ParsePrefix)
}
func ParseAddrPorts(ss []string) ([]netip.AddrPort, error) {
	return FromStringSlice(ss, netip.ParseAddrPort)
}
func SliceMap[T1 any, T2 any](from []T1, mapFn func(T1) (T2, error)) ([]T2, error) {
	list := make([]T2, 0, len(from))
	for _, v := range from {
		to, err := mapFn(v)
		if err != nil {
			return nil, err
		}
		list = append(list, to)
	}
	return list, nil
}
func SliceFilter[T any](s []T, test func(v T) bool) []T {
	var list []T
	for _, v := range s {
		if test(v) {
			list = append(list, v)
		}
	}
	return list
}