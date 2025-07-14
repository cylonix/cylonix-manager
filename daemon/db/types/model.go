// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// Common table model.
type Model struct {
	ID        ID `gorm:"type:uuid;primarykey"`
	CreatedAt time.Time
	UpdatedAt time.Time

	// Not including soft-delete for now.
	// DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (m *Model) BeforeCreate(tx *gorm.DB) error {
	table := "unknown"
	if tx.Statement != nil {
		table = tx.Statement.Table
	}
	if m.ID.IsNil() {
		return fmt.Errorf("%v entry's id is nil", table)
	}
	return nil
}

func (m *Model) SetIDIfNil() error {
	if m == nil {
		return errors.New("model is nil")
	}
	if m.ID.IsNil() {
		id, err := NewID()
		if err != nil {
			return err
		}
		m.ID = id
	}
	return nil
}
