// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/cylonix/utils/postgres"
	"gorm.io/gorm"
)

func filter(pg *gorm.DB, filterBy, filterValue *string) *gorm.DB {
	if filterBy != nil && filterValue != nil && *filterBy != "" && *filterValue != "" {
		pg = pg.Where(*filterBy+" like ?", like(*filterValue))
	}
	return pg
}

func filterExact(pg *gorm.DB, filterBy *string, filterValue interface{}) *gorm.DB {
	if filterBy != nil && filterValue != nil && *filterBy != "" {
		pg = pg.Where(*filterBy+" = ?", filterValue)
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
