// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseResourceKey(t *testing.T) {
	// Well-formed: /cylonix/global/<uuid>/<type>
	uuid, rType, err := parseResourceKey("/cylonix/global/abc/wg")
	assert.NoError(t, err)
	assert.Equal(t, "abc", uuid)
	assert.Equal(t, "wg", rType)

	_, _, err = parseResourceKey("too/short")
	assert.Error(t, err)
}

func TestNewResourceService(t *testing.T) {
	s := NewResourceService(nil)
	assert.NotNil(t, s)
	assert.NotNil(t, s.namespaces)
	assert.NotNil(t, s.derpers)
	assert.NotNil(t, s.wgResource)
	assert.NotNil(t, s.namespaceResource)
	assert.NotNil(t, s.popResource)
	assert.NotNil(t, s.taiResource)
}
