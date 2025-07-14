// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/optional"
	"time"
)

type HistoryEntry struct {
	Model
	UpdaterID     *UserID `gorm:"type:uuid"`
	UpdaterName   *string
	NetworkDomain *string
	Note          string
}

type History []HistoryEntry

func NewHistoryEntry(updaterID *UserID, updaterName, networkDomain *string, note string) (*HistoryEntry, error) {
	id, err := NewID()
	if err != nil {
		return nil, err
	}
	return &HistoryEntry{
		Model:         Model{ID: id},
		UpdaterID:     updaterID.NotNilP(),
		UpdaterName:   updaterName,
		NetworkDomain: networkDomain,
		Note:          note,
	}, nil
}

func (e *HistoryEntry) ToModel() *models.UpdateHistoryEntry {
	return &models.UpdateHistoryEntry{
		ID:          e.ID.UUID(),
		Timestamp:   e.CreatedAt.Unix(),
		Note:        e.Note,
		UpdaterID:   e.UpdaterID.UUID(),
		UpdaterName: optional.String(e.UpdaterName),
	}
}

func (e *HistoryEntry) FromModel(m *models.UpdateHistoryEntry) *HistoryEntry {
	return &HistoryEntry{
		Model: Model{
			ID:        UUIDToID(m.ID),
			CreatedAt: time.Unix(m.Timestamp, 0).UTC(),
		},
		Note:        m.Note,
		UpdaterID:   UUIDPToID(&m.UpdaterID),
		UpdaterName: optional.StringP(m.UpdaterName),
	}
}

func (h History) ToModel() []models.UpdateHistoryEntry {
	var m []models.UpdateHistoryEntry
	for _, e := range h {
		m = append(m, *e.ToModel())
	}
	return m
}

func (h History) FromModel(m []models.UpdateHistoryEntry) History {
	for _, e := range m {
		v := &HistoryEntry{}
		h = append(h, *v.FromModel(&e))
	}
	return h
}
