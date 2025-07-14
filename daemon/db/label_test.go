// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/daemon/db/types"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLabelDB(t *testing.T) {
	namespace := "test-namespace"
	labelIDs, labelNames := make([]types.LabelID, 10), make([]string, 10)
	for i := 0; i < 10; i++ {
		id, err := types.NewID()
		if !assert.Nil(t, err) {
			return
		}
		labelNames[i] = fmt.Sprintf("test-label-name-%v", i)
		label := &types.Label{
			Namespace: namespace,
			Name:      labelNames[i],
		}
		if i % 2 == 0 {
			label.Scope = &types.NilID
		}
		label.ID = id
		err = CreateLabel(label)
		if !assert.Nil(t, err) {
			return
		}
		labelIDs[i] = label.ID
	}

	// Should return an entry if only to label label ID.
	getLabel, err := GetLabel(namespace, nil, labelIDs[0])
	if assert.Nil(t, err) && assert.NotNil(t, getLabel) {
		assert.Equal(t, getLabel.ID, labelIDs[0])
		assert.Equal(t, getLabel.Name, labelNames[0])
	}

	// Nil scope should not match a label with non-nil scope.
	var scope *types.ID
	getLabel, err = GetLabel(namespace, &scope, labelIDs[0])
	assert.ErrorIs(t, err, ErrLabelNotExists)
	assert.Nil(t, getLabel)

	// Matching scope should return an entry.
	scope = &types.NilID
	getLabel, err = GetLabel(namespace, &scope, labelIDs[0])
	if assert.Nil(t, err) && assert.NotNil(t, getLabel) {
		assert.Equal(t, getLabel.ID, labelIDs[0])
		assert.Equal(t, getLabel.Name, labelNames[0])
	}

	total, labels, err := GetLabelList(&namespace, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, int(total))
		assert.Len(t, labels, 10)
	}
	scope = &types.NilID
	total, labels, err = GetLabelList(&namespace, []*types.ID{scope}, nil, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 5, int(total))
		assert.Len(t, labels, 5)
	}
	scope = nil
	total, labels, err = GetLabelList(&namespace, []*types.ID{nil}, nil, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 5, int(total))
		assert.Len(t, labels, 5)
	}
	total, labels, err = GetLabelList(&namespace, []*types.ID{nil, &types.NilID}, nil, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, int(total))
		assert.Len(t, labels, 10)
	}
	total, labels, err = GetLabelList(&namespace, nil, &labelNames[3], nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, int(total), 1)
		assert.Len(t, labels, 1)
	}

	err = UpdateLabels(namespace, nil, []types.LabelID{labelIDs[0]}, types.Label{Color: "green"})
	assert.Nil(t, err)
	getLabel, err = GetLabel(namespace, nil, labelIDs[0])
	if assert.Nil(t, err) {
		assert.Equal(t, getLabel.Color, "green")
	}
	err = UpdateLabel(namespace, nil, labelIDs[0], types.Label{Name: "new name"})
	assert.Nil(t, err)
	getLabel, err = GetLabel(namespace, nil, labelIDs[0])
	if assert.Nil(t, err) {
		assert.Equal(t, getLabel.Name, "new name")
	}
	err = DeleteLabel(namespace, nil, labelIDs[5])
	assert.Nil(t, err)
	_, err = GetLabel(namespace, nil, labelIDs[5])
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrLabelNotExists)
	}
}
