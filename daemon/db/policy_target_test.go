package db

import (
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testPolicyTargetNamespace = "test-namespace"
	testPolicyTargetName = "test target"
)

func TestCreatePolicyTarget(t *testing.T) {
	namespace := testPolicyTargetNamespace

	target := &types.PolicyTarget{}
	err := CreatePolicyTarget(nil)
	assert.NotNil(t, err, ErrBadParams)
	err = CreatePolicyTarget(target)
	assert.NotNil(t, err, ErrBadParams)

	target = &types.PolicyTarget{Namespace: namespace, Name: testPolicyTargetName}
	err = CreatePolicyTarget(target)
	assert.Nil(t, err)
	assert.Nil(t, DeletePolicyTarget(namespace, target.ID, true))
}

func TestGetPolicyTarget(t *testing.T) {
	namespace := testPolicyTargetNamespace
	target := &types.PolicyTarget{Namespace: namespace, Name: testPolicyTargetName}
	err := CreatePolicyTarget(target)
	assert.Nil(t, err)
	testPolicyTargetID := target.ID
	defer func() {
		assert.Nil(t, DeletePolicyTarget(namespace, testPolicyTargetID, true))
	}()

	_, err = GetPolicyTarget(namespace, types.NilID)
	assert.NotNil(t, err, ErrBadParams)

	_, err = GetPolicyTarget("", testPolicyTargetID)
	assert.NotNil(t, err, ErrBadParams)

	target, err = GetPolicyTarget(namespace, testPolicyTargetID)
	if assert.Nil(t, err) && assert.NotNil(t, target) && assert.NotNil(t, target.Name) {
		assert.Equal(t, testPolicyTargetName, target.Name)
	}
}

func TestUpdatePolicyTarget(t *testing.T) {
	namespace := testPolicyTargetNamespace
	id, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	err = UpdatePolicyTarget(namespace, types.NilID, nil)
	assert.NotNil(t, err, ErrBadParams)
	err = UpdatePolicyTarget(namespace, id, nil)
	assert.NotNil(t, err, ErrBadParams)
	update := types.PolicyTarget{Model: types.Model{ID: id}}
	err = UpdatePolicyTarget(namespace, id, &update)
	assert.NotNil(t, err, ErrBadParams)

	target := &types.PolicyTarget{Namespace: namespace, Name: testPolicyTargetName}
	err = CreatePolicyTarget(target)
	if !assert.Nil(t, err) {
		return
	}
	testPolicyTargetID := target.ID
	defer func() {
		assert.Nil(t, DeletePolicyTarget(namespace, testPolicyTargetID, true))
	}()

	update = types.PolicyTarget{Name: testPolicyTargetName}
	err = UpdatePolicyTarget(namespace, testPolicyTargetID, &update)
	assert.Nil(t, err)

	update = types.PolicyTarget{ReadOnly: optional.BoolP(true)}
	err = UpdatePolicyTarget(namespace, testPolicyTargetID, &update)
	assert.Nil(t, err)
	target, err = GetPolicyTarget(namespace, testPolicyTargetID)
	assert.Nil(t, err)
	if assert.NotNil(t, target) {
		assert.True(t, optional.Bool(target.ReadOnly))
	}

	update = types.PolicyTarget{Name: "new name"}
	err = UpdatePolicyTarget(namespace, testPolicyTargetID, &update)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrPolicyTargetReadOnly)
	}
}
func TestDeletePolicyTarget(t *testing.T) {
	namespace := testPolicyTargetNamespace
	target := &types.PolicyTarget{Namespace: namespace, Name: testPolicyTargetName}
	err := CreatePolicyTarget(target)
	if !assert.Nil(t, err) {
		return
	}
	testPolicyTargetID := target.ID
	defer func() {
		assert.Nil(t, DeletePolicyTarget(namespace, testPolicyTargetID, true))
	}()

	badID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}

	err = DeletePolicyTarget("", testPolicyTargetID, false)
	assert.ErrorIs(t, err, ErrBadParams)

	err = DeletePolicyTarget(namespace, types.NilID, false)
	assert.ErrorIs(t, err, ErrBadParams)
	assert.Nil(t, DeletePolicyTarget(namespace, badID, false))

	update := types.PolicyTarget{ReadOnly: optional.BoolP(true)}
	err = UpdatePolicyTarget(namespace, testPolicyTargetID, &update)
	assert.Nil(t, err)
	err = DeletePolicyTarget(namespace, testPolicyTargetID, false)
	assert.ErrorIs(t, err, ErrPolicyTargetReadOnly)
}

func TestListPolicyTarget(t *testing.T) {
	namespace := testPolicyTargetNamespace
	names, ids := make([]string, 10), make([]types.PolicyTargetID, 10)
	for i := 0; i < 10; i++ {
		names[i] = fmt.Sprintf("%v-%v", testPolicyTargetName, i)
		target := &types.PolicyTarget{Namespace: namespace, Name: names[i]}
		err := CreatePolicyTarget(target)
		if !assert.Nil(t, err) {
			t.Fatalf("Failed to create policy target: %v", err)
		}
		ids[i] = target.ID
	}
	defer func() {
		for _, id := range ids {
			assert.Nil(t, DeletePolicyTarget(testPolicyTargetNamespace, id, true))
		}
	}()

	total, targets, err := ListPolicyTarget(testPolicyTargetNamespace, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, int(total))
		assert.Equal(t, 10, len(targets))
	}

	total, targets, err = ListPolicyTarget(testPolicyTargetNamespace, &names[1], nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 1, int(total))
		if assert.Equal(t, 1, len(targets)) {
			if assert.NotNil(t, targets[0].ID) {
				assert.Equal(t, ids[1], targets[0].ID)
			}
			if assert.NotNil(t, targets[0].Name) {
				assert.Equal(t, names[1], targets[0].Name)
			}
		}
	}

	total, targets, err = ListPolicyTarget(testPolicyTargetNamespace, &testPolicyTargetName, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, int(total))
		assert.Equal(t, 10, len(targets))
	}

	filterBy := "name"
	total, targets, err = ListPolicyTarget(testPolicyTargetNamespace, &testPolicyTargetName, &filterBy, &names[5], nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 1, int(total))
		if assert.Equal(t, 1, len(targets)) {
			if assert.NotNil(t, targets[0].ID) {
				assert.Equal(t, ids[5], targets[0].ID)
			}
			if assert.NotNil(t, targets[0].Name) {
				assert.Equal(t, names[5], targets[0].Name)
			}
		}
	}

	sortBy := "name"
	sortDesc := "desc"
	total, targets, err = ListPolicyTarget(testPolicyTargetNamespace, &testPolicyTargetName, nil, nil, &sortBy, &sortDesc, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, int(total))
		if assert.Equal(t, 10, len(targets)) {
			if assert.NotNil(t, targets[9].ID) {
				assert.Equal(t, ids[0], targets[9].ID)
			}
			if assert.NotNil(t, targets[9].Name) {
				assert.Equal(t, names[0], targets[9].Name)
			}
		}
	}

	page := 2
	pageSize := 5
	total, targets, err = ListPolicyTarget(testPolicyTargetNamespace, nil, nil, nil, &sortBy, nil, &page, &pageSize)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, int(total))
		if assert.Equal(t, 5, len(targets)) {
			if assert.NotNil(t, targets[4].ID) {
				assert.Equal(t, ids[9], targets[4].ID)
			}
			if assert.NotNil(t, targets[4].Name) {
				assert.Equal(t, names[9], targets[4].Name)
			}
		}
	}
}
