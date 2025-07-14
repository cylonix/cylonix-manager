// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var (
	tenantTestCompanyName          = "test-tenant-company-name"
	tenantTestCompanyNameNotExists = "test-tenant-company-name-not-exists"
	tenantTestNamespace            = "test-tenant-namespace"
	tenantTestNamespaceNotExists   = "test-tenant-namespace-not-exists"
	tenantTestEmail                = "test@a.com"
	tenantTestPhone                = "1234567890"
)

func TestTenantApproval(t *testing.T) {
	names, ids := make([]string, 10), make([]types.TenantApprovalID, 10)
	approverName, note := "sys-admin", "test-tenant-approval"
	approverID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}

	// Create
	for i := 0; i < 10; i++ {
		names[i] = fmt.Sprintf("%v-%v", tenantTestCompanyName, i)
		r := &models.TenantApproval{
			CompanyName: names[i],
			Email:       names[i] + "@example.com",
		}
		a, err := NewTenantApproval(r, approverID, approverName, note)
		if !assert.Nil(t, err) {
			t.Fatalf("Failed to create tenant approval: %v", err)
		}
		ids[i] = a.ID
	}
	defer func() {
		for _, id := range ids {
			assert.Nil(t, DeleteTenantApproval(id))
		}
	}()
	r := &models.TenantApproval{CompanyName: names[0]}
	_, err = NewTenantApproval(r, approverID, approverName, note)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrTenantApprovalExists)
	}

	// Get
	badID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	_, err = GetTenantApproval(badID)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrTenantApprovalNotExists)
	}
	_, err = GetTenantApproval(ids[0])
	assert.Nil(t, err)
	_, err = GetTenantApprovalByName(tenantTestCompanyNameNotExists)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrTenantApprovalNotExists)
	}
	_, err = GetTenantApprovalByNamespace(tenantTestNamespaceNotExists)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrTenantApprovalNotExists)
	}

	// Update
	err = SetTenantApprovalState(ids[0], models.ApprovalStateApproved, approverID, approverName, note)
	assert.Nil(t, err)
	c, err := GetTenantApproval(ids[0])
	assert.Nil(t, err)
	if assert.NotNil(t, c) {
		assert.Equal(t, names[0], c.CompanyName)
		assert.Equal(t, string(models.ApprovalStateApproved), string(c.ApprovalState))
	}

	// List
	list, total, err := ListTenantApproval(nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, total)
		assert.NotNil(t, list)
	}
	list, total, err = ListTenantApproval(nil, &names[3], nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 1, total)
		if assert.Equal(t, 1, len(list)) {
			assert.Equal(t, names[3], list[0].CompanyName)
		}
	}
	list, total, err = ListTenantApproval(nil, &tenantTestCompanyName, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, total)
		assert.Equal(t, 10, len(list))
	}
	list, total, err = ListTenantApproval(nil, nil, nil, nil, nil, nil, []types.ID{ids[4], ids[5]}, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 2, total)
		assert.Equal(t, 2, len(list))
	}
	page, pageSize := 2, 5
	list, total, err = ListTenantApproval(nil, nil, nil, nil, nil, nil, nil, &page, &pageSize)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, total)
		assert.Equal(t, 5, len(list))
	}
	sortBy, sortDesc := "company_name", "desc"
	list, total, err = ListTenantApproval(nil, nil, nil, nil, &sortBy, &sortDesc, nil, &page, &pageSize)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, total)
		if assert.Equal(t, 5, len(list)) {
			assert.Equal(t, names[0], list[4].CompanyName)
		}
	}
	pending := string(models.ApprovalStatePending)
	list, total, err = ListTenantApproval(&pending, nil, nil, nil, &sortBy, &sortDesc, nil, &page, &pageSize)
	if assert.Nil(t, err) {
		assert.Equal(t, 9, total)
		assert.Equal(t, 4, len(list))
	}

	// Delete
	err = DeleteTenantApproval(types.NilID)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrTenantApprovalIDInvalid)
	}
	assert.Nil(t, DeleteTenantApproval(badID))
	assert.Nil(t, DeleteTenantApproval(ids[5]))
	list, total, err = ListTenantApproval(nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.NotNil(t, list)
		assert.Equal(t, 9, total)
		assert.Equal(t, 9, len(list))
	}
}

func TestTenantConfig(t *testing.T) {
	names, ids := make([]string, 10), make([]types.TenantID, 10)

	{
		list, total, err := ListTenantConfig(nil, nil, nil, nil, nil, nil, nil, nil)
		if assert.Nil(t, err) {
			assert.Equal(t, 0, total)
			if !assert.Equal(t, 0, len(list)) {
				v, _ := json.Marshal(list)
				fmt.Println(string(v))
				return
			}
		}
	}

	tier, err := createUserTierForTest()
	if !assert.Nil(t, err) {
		return
	}

	// Create
	for i := 0; i < 10; i++ {
		names[i] = fmt.Sprintf("%v-%v", tenantTestNamespace, i)
		c, err := NewTenantForNamespace(
			names[i], names[i], names[i]+"@example.com", uuid.New().String(),
			nil, nil, &tier.ID, false,
		)
		if !assert.Nil(t, err) || !assert.NotNil(t, c) {
			t.Fatalf("Failed to create tenant: %v", err)
		}
		ids[i] = c.ID
	}
	defer func() {
		for _, id := range ids {
			assert.Nil(t, DeleteTenantConfig(id))
		}
	}()
	_, err = NewTenantForNamespace(names[0], names[0], "", "", nil, nil, nil, false)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrTenantExists)
	}

	// Get
	c, err := GetTenantConfig(ids[0])
	if assert.Nil(t, err) && assert.NotNil(t, c) {
		assert.Equal(t, names[0], c.Namespace)
	}
	_, err = GetTenantConfig(types.NilID)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrTenantIDInvalid)
	}
	badID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	_, err = GetTenantConfig(badID)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrTenantNotExists)
	}

	// Update
	update := types.TenantConfig{
		Email: &tenantTestEmail,
		Phone: &tenantTestPhone,
	}
	err = UpdateTenantConfig(c.ID, update, types.NilID, "", "test")
	if assert.Nil(t, err) {
		c, err = GetTenantConfig(c.ID)
		if assert.Nil(t, err) && assert.NotNil(t, c) && assert.NotNil(t, c.Phone) && assert.NotNil(t, c.Email){
			assert.Equal(t, tenantTestEmail, *c.Email)
			assert.Equal(t, tenantTestPhone, *c.Phone)
		}
	}

	update = types.TenantConfig{
		TenantSetting: types.TenantSetting{AutoAcceptRoutes: optional.BoolP(true)},
	}
	err = UpdateTenantConfig(c.ID, update, types.NilID, "", "test")
	if assert.Nil(t, err) {
		c, err = GetTenantConfig(c.ID)
		if assert.Nil(t, err) && assert.NotNil(t, c) && assert.NotNil(t, c.AutoAcceptRoutes) {
			assert.True(t, *c.AutoAcceptRoutes)
		}
	}

	// List
	list, total, err := ListTenantConfig(nil, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, total)
		assert.Equal(t, 10, len(list))
	}
	list, total, err = ListTenantConfig(&tenantTestNamespace, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, total)
		assert.Equal(t, 10, len(list))
	}
	list, total, err = ListTenantConfig(&names[0], nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 1, total)
		assert.Equal(t, 1, len(list))
	}
	var idList = []types.ID{ids[1], ids[3], ids[5]}
	list, total, err = ListTenantConfig(nil, nil, nil, nil, nil, idList, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, len(idList), total)
		assert.Equal(t, len(idList), len(list))
	}
	filterBy := "namespace"
	list, total, err = ListTenantConfig(nil, &filterBy, &names[3], nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 1, total)
		assert.Equal(t, 1, len(list))
	}
	sortBy, sortDesc := "name", "desc"
	list, total, err = ListTenantConfig(nil, nil, nil, &sortBy, &sortDesc, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 10, total)
		if assert.Equal(t, 10, len(list)) {
			assert.Equal(t, names[0], list[9].Namespace)
		}
	}
}
