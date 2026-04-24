// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package optional

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInt64(t *testing.T) {
	v := int64(42)
	assert.Equal(t, int64(42), Int64(&v))
	assert.Equal(t, int64(0), Int64(nil))
}

func TestInt(t *testing.T) {
	v := 7
	assert.Equal(t, 7, Int(&v))
	assert.Equal(t, 0, Int(nil))
}

func TestAddIntP(t *testing.T) {
	assert.Equal(t, 5, *AddIntP(nil, 5))
	v := 3
	assert.Equal(t, 8, *AddIntP(&v, 5))
}

func TestAddInt64P(t *testing.T) {
	assert.Equal(t, int64(5), *AddInt64P(nil, 5))
	v := int64(3)
	assert.Equal(t, int64(8), *AddInt64P(&v, 5))
}

func TestAddInt64PIfNotNil(t *testing.T) {
	a := int64(1)
	v := int64(2)
	assert.Equal(t, int64(3), *AddInt64PIfNotNil(&a, &v))
	// v nil returns a unchanged
	assert.Equal(t, &a, AddInt64PIfNotNil(&a, nil))
}

func TestAddUint64P(t *testing.T) {
	assert.Equal(t, uint64(5), *AddUint64P(nil, 5))
	v := uint64(3)
	assert.Equal(t, uint64(8), *AddUint64P(&v, 5))
}

func TestAddUint64PIfNotNil(t *testing.T) {
	a := uint64(1)
	v := uint64(2)
	assert.Equal(t, uint64(3), *AddUint64PIfNotNil(&a, &v))
	assert.Equal(t, &a, AddUint64PIfNotNil(&a, nil))
}

func TestStringP(t *testing.T) {
	p := StringP("hello")
	assert.Equal(t, "hello", *p)
}

func TestNilIfEmptyStringP(t *testing.T) {
	assert.Nil(t, NilIfEmptyStringP(""))
	p := NilIfEmptyStringP("x")
	assert.Equal(t, "x", *p)
}

func TestCopyStringP(t *testing.T) {
	assert.Nil(t, CopyStringP(nil))
	s := "hi"
	p := CopyStringP(&s)
	assert.Equal(t, "hi", *p)
	// confirm it's a copy
	*p = "changed"
	assert.Equal(t, "hi", s)
}

func TestIntPAndInt64P(t *testing.T) {
	assert.Equal(t, 5, *IntP(5))
	assert.Equal(t, int64(7), *Int64P(7))
}

func TestUint(t *testing.T) {
	v := uint(42)
	assert.Equal(t, uint(42), Uint(&v))
	assert.Equal(t, uint(0), Uint(nil))
}

func TestUint64(t *testing.T) {
	v := uint64(42)
	assert.Equal(t, uint64(42), Uint64(&v))
	assert.Equal(t, uint64(0), Uint64(nil))
}

func TestUint64P(t *testing.T) {
	assert.Equal(t, uint64(8), *Uint64P(8))
}

func TestCopyUint64P(t *testing.T) {
	assert.Nil(t, CopyUint64P(nil))
	v := uint64(3)
	p := CopyUint64P(&v)
	assert.Equal(t, uint64(3), *p)
}

func TestUintPToUint64P(t *testing.T) {
	assert.Nil(t, UintPToUint64P(nil))
	v := uint(5)
	p := UintPToUint64P(&v)
	assert.Equal(t, uint64(5), *p)
}

func TestUint64PToUintP(t *testing.T) {
	assert.Nil(t, Uint64PToUintP(nil))
	v := uint64(5)
	p := Uint64PToUintP(&v)
	assert.Equal(t, uint(5), *p)
}

func TestString(t *testing.T) {
	s := "abc"
	assert.Equal(t, "abc", String(&s))
	assert.Equal(t, "", String(nil))
}

func TestStringSlice(t *testing.T) {
	s := []string{"a", "b"}
	assert.Equal(t, s, StringSlice(&s))
	assert.Equal(t, []string{}, StringSlice(nil))
}

func TestBool(t *testing.T) {
	b := true
	assert.True(t, Bool(&b))
	assert.False(t, Bool(nil))
}

func TestBoolP(t *testing.T) {
	assert.True(t, *BoolP(true))
}

func TestCopyBoolP(t *testing.T) {
	assert.Nil(t, CopyBoolP(nil))
	b := true
	p := CopyBoolP(&b)
	assert.True(t, *p)
}

func TestGenericP(t *testing.T) {
	p := P(10)
	assert.Equal(t, 10, *p)
	p2 := P("s")
	assert.Equal(t, "s", *p2)
}

func TestGenericV(t *testing.T) {
	var nilPtr *int
	assert.Equal(t, 5, V(nilPtr, 5))
	n := 7
	assert.Equal(t, 7, V(&n, 0))
}

func TestGenericCopyP(t *testing.T) {
	var nilPtr *int
	assert.Nil(t, CopyP(nilPtr))
	n := 3
	p := CopyP(&n)
	assert.Equal(t, 3, *p)
	*p = 100
	assert.Equal(t, 3, n)
}
