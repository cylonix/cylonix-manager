// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrNotImplemented(t *testing.T) {
	err := ErrNotImplemented("foo")
	assert.Contains(t, err.Error(), "foo")
	assert.Contains(t, err.Error(), "not implemented")
}
