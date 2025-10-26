// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/cylonix/utils/postgres"
	"gorm.io/gorm"
)

func filter(pg *gorm.DB, filterBy, filterValue *string) *gorm.DB {
	if filterBy != nil && filterValue != nil && *filterBy != "" && *filterValue != "" {
		by := strings.Split(*filterBy, ",")
		value := strings.Split(*filterValue, ",")
		if len(by) != len(value) {
			return pg
		}
		for i := range by {
			pg = pg.Where(by[i]+" like ?", like(value[i]))
		}
	}
	return pg
}

func filterExact(pg *gorm.DB, filterBy *string, filterValues []interface{}) *gorm.DB {
	if filterBy != nil && filterValues != nil && *filterBy != "" {
		by := strings.Split(*filterBy, ",")
		if len(by) != len(filterValues) {
			return pg
		}
		for i := range by {
			pg = pg.Where(by[i]+" = ?", filterValues[i])
		}
	}
	return pg
}

func interfaceHasNilValue(i interface{}) bool {
   if i == nil {
      return true
   }
   switch reflect.TypeOf(i).Kind() {
   case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
      return reflect.ValueOf(i).IsNil()
   }
   return false
}

func whereCheckNil(pg *gorm.DB, column string, value interface{}) *gorm.DB {
	if interfaceHasNilValue(value) {
		return pg.Where(column + " is NULL")
	}
	return pg.Where(column + " = ?", value)
}

func pgCheckError(err, notFoundErr error) error {
	if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
		return notFoundErr
	}
	return err
}

func getPGconn() (*gorm.DB, error) {
	db, err := postgres.Connect()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPGConnection, err)
	}
	return db, nil
}

func BeginTransaction() (*gorm.DB, error) {
	db, err := getPGconn()
	if err != nil {
		return nil, err
	}
	tx := db.Begin()
	if err := tx.Error; err != nil {
		return nil, err
	}
	return tx, nil
}