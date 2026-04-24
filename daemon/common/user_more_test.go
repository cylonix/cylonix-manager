// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNamespaceRootUserNetworkDomain(t *testing.T) {
	assert.Equal(t, "system-internal.ns1", NamespaceRootUserNetworkDomain("ns1"))
}

func TestIsNamespaceRootUser(t *testing.T) {
	assert.True(t, IsNamespaceRootUser("root"))
	assert.True(t, IsNamespaceRootUser("system-internal"))
	assert.False(t, IsNamespaceRootUser("alice"))
}

func TestGetOrCreateDefaultUserTier(t *testing.T) {
	// Creates tier if not exists, else returns existing.
	tier, err := GetOrCreateDefaultUserTier()
	assert.NoError(t, err)
	assert.NotNil(t, tier)

	tier2, err := GetOrCreateDefaultUserTier()
	assert.NoError(t, err)
	assert.Equal(t, tier.ID, tier2.ID)
}

func TestNewDefaultTenant(t *testing.T) {
	// Use a unique creator name to avoid colliding with other tests
	// that may create the default tenant.
	_, err := NewDefaultTenant("user-more-test-creator", "note")
	_ = err
}
