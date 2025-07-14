// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"encoding/binary"
	"fmt"

	"database/sql/driver"

	"github.com/google/uuid"
)

type ID uuid.UUID

var (
	NilID = UUIDToID(uuid.Nil)
)

func NewID() (ID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		err = fmt.Errorf("failed to generate new id: %w", err)
	}
	return ID(id), err
}

func ParseID(s string) (ID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		err = fmt.Errorf("failed to parse id: %w", err)
	}
	return ID(id), err
}

func UUIDToID(u uuid.UUID) ID {
	v := ID(u)
	return v
}

func UUIDPToID(u *uuid.UUID) *ID {
	if u == nil {
		return nil
	}
	v := ID(*u)
	if v.IsNil() {
		return nil
	}
	return &v
}

func (id *ID) UUID() uuid.UUID {
	if id == nil {
		return uuid.Nil
	}
	v := uuid.UUID(*id)
	return v
}

func (id *ID) UUIDP() *uuid.UUID {
	if id == nil || id.IsNil() {
		return nil
	}
	v := uuid.UUID(*id)
	return &v
}

func (id *ID) Copy(from *ID) *ID {
	if from == nil {
		return nil
	}
	v := *from
	return &v
}

func (id *ID) NotNilP() *ID {
	if id != nil && id.IsNil() {
		return nil
	}
	return id
}

func (id *ID) StringP() *string {
	if id == nil {
		return nil
	}
	v := id.String()
	return &v
}

func (id *ID) Scan(value interface{}) error {
	t, ok := value.([]byte)
	if !ok {
		// Postgres actually stores in bytes but returns hex string in query.
		t, ok := value.(string)
		if ok {
			v, err := uuid.Parse(t)
			if err != nil {
				return err
			}
			*id = ID(v)
			return nil
		}
		return fmt.Errorf("invalid id value type: %T(%v)", value, value)
	}
	v, err := uuid.FromBytes(t)
	if err != nil {
		return err
	}
	*id = ID(v)
	return nil
}
func (id ID) Value() (driver.Value, error) {
	return uuid.UUID(id).MarshalBinary()
}

func (id ID) IsNil() bool {
	return uuid.UUID(id) == uuid.Nil
}

func (id ID) String() string {
	return uuid.UUID(id).String()
}

// Uint64 returns the random part of the v7 uuid. i.e. last 8 bytes.
func (id ID) Uint64() uint64 {
	return binary.BigEndian.Uint64(id[8:])
}

type IDList []ID

func (list IDList) FromUUIDList(l []uuid.UUID) []ID {
	return UUIDListToIDList(&l)
}
func (list IDList) StringSlice() []string {
	var ss []string
	for _, l := range list {
		ss = append(ss, l.String())
	}
	return ss
}

func UUIDListToIDList(l *[]uuid.UUID) []ID {
	if l == nil {
		return nil
	}
	var ret IDList
	for _, v := range *l {
		ret = append(ret, UUIDToID(v))
	}
	return ret
}
