// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/daemon/db/types"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicy(t *testing.T) {
	namespace := "test-namespace"
	targetID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	targetName := "test-policy-target-name"
	err = CreatePolicyTarget(&types.PolicyTarget{
		Model:     types.Model{ID: targetID},
		Namespace: namespace,
		Name:      targetName,
	})
	if !assert.Nil(t, err) {
		return
	}

	policyIDs, policyNames := make([]types.PolicyID, 10), make([]string, 10)
	for i := 0; i < 10; i++ {
		id, err := types.NewID()
		if !assert.Nil(t, err) {
			return
		}
		policyIDs[i] = id
		policyNames[i] = fmt.Sprintf("test-policy-name-%v", i)
		err = CreatePolicy(&types.Policy{
			Namespace:      namespace,
			Model:          types.Model{ID: id},
			Name:           policyNames[i],
			PolicyTargetID: &targetID,
		})
		if !assert.Nil(t, err) {
			return
		}
	}

	getPolicy, err := GetPolicy(namespace, policyIDs[0])
	if assert.Nil(t, err) {
		assert.Equal(t, getPolicy.ID, policyIDs[0])
	}

	total, policies, err := GetPolicyList(namespace, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, int(total), 10)
		assert.Equal(t, len(policies), 10)
	}
	filterBy := "name"
	total, policies, err = GetPolicyList(namespace, nil, &filterBy, &policyNames[3], nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, int(total), 1)
		assert.Equal(t, len(policies), 1)
	}

	err = UpdatePolicyName(namespace, policyIDs[5], "123456")
	assert.Nil(t, err)
	getPolicy, err = GetPolicy(namespace, policyIDs[5])
	if assert.Nil(t, err) {
		assert.Equal(t, getPolicy.Name, "123456")
	}

	list, err := PolicyListOfTargetID(namespace, targetID)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, len(list))
	}
	count, err := TargetPolicyCount(namespace, targetID)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, int(count))
	}

	err = DeletePolicy(namespace, policyIDs[3])
	assert.Nil(t, err)
	_, err = GetPolicy(namespace, policyIDs[3])
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrPolicyNotExists)
	}
}
