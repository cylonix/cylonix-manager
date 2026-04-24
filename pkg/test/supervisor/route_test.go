// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package supervisor_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRouteClientEmulator(t *testing.T) {
	r := &RouteClientEmulator{}
	assert.NoError(t, r.CreateNamespaceAppRoute("ns", nil))
	assert.NoError(t, r.DeleteNamespaceAppRoute("ns", nil))
}
