// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewBadRequestErrorCode(t *testing.T) {
	ec := NewBadRequestErrorCode(errors.New("some-code"))
	assert.NotNil(t, ec)
	assert.Equal(t, "some-code", string(*ec))
}

func TestNewBadRequestJSONResponse(t *testing.T) {
	// Plain error.
	r := NewBadRequestJSONResponse(errors.New("e"))
	assert.NotNil(t, r.ErrorCode)
	assert.Nil(t, r.ErrorMessage)

	// CodedError (BadParamsErr).
	cp := NewBadParamsErr(errors.New("bad"))
	r = NewBadRequestJSONResponse(cp)
	assert.NotNil(t, r.ErrorCode)
	assert.NotNil(t, r.ErrorMessage)
	assert.Equal(t, "bad", *r.ErrorMessage)
}

func TestBadParamsErr_Methods(t *testing.T) {
	e := NewBadParamsErr(errors.New("msg"))
	assert.Equal(t, "msg", e.Error())
	assert.Equal(t, "err_bad_params", e.Code())
	assert.Equal(t, "msg", e.ToString())
}

func TestConflictErr_Methods(t *testing.T) {
	e := NewConflictErr(errors.New("conflict"))
	assert.Equal(t, "conflict", e.Error())
}
