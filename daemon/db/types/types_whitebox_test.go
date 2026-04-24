// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewID(t *testing.T) {
	id, err := NewID()
	assert.NoError(t, err)
	assert.False(t, id.IsNil())
}

func TestParseID(t *testing.T) {
	u := uuid.New()
	id, err := ParseID(u.String())
	assert.NoError(t, err)
	assert.Equal(t, u.String(), id.String())

	_, err = ParseID("bogus")
	assert.Error(t, err)
}

func TestUUIDToID(t *testing.T) {
	u := uuid.New()
	id := UUIDToID(u)
	assert.Equal(t, u.String(), id.String())
}

func TestUUIDPToID(t *testing.T) {
	assert.Nil(t, UUIDPToID(nil))
	u := uuid.UUID{}
	assert.Nil(t, UUIDPToID(&u))
	nn := uuid.New()
	assert.NotNil(t, UUIDPToID(&nn))
}

func TestID_UUID(t *testing.T) {
	var nilID *ID
	assert.Equal(t, uuid.Nil, nilID.UUID())
	u := uuid.New()
	id := UUIDToID(u)
	assert.Equal(t, u, id.UUID())
}

func TestID_UUIDP(t *testing.T) {
	var nilID *ID
	assert.Nil(t, nilID.UUIDP())
	id := UUIDToID(uuid.Nil)
	assert.Nil(t, id.UUIDP())

	u := uuid.New()
	id = UUIDToID(u)
	assert.Equal(t, u, *id.UUIDP())
}

func TestID_Copy(t *testing.T) {
	var nilID *ID
	assert.Nil(t, nilID.Copy(nil))
	from := UUIDToID(uuid.New())
	out := from.Copy(&from)
	assert.Equal(t, from, *out)
}

func TestID_NotNilP(t *testing.T) {
	var nilID *ID
	assert.Nil(t, nilID.NotNilP())
	zero := UUIDToID(uuid.Nil)
	assert.Nil(t, zero.NotNilP())
	v := UUIDToID(uuid.New())
	assert.NotNil(t, v.NotNilP())
}

func TestID_StringP(t *testing.T) {
	var nilID *ID
	assert.Nil(t, nilID.StringP())
	v := UUIDToID(uuid.New())
	assert.Equal(t, v.String(), *v.StringP())
}

func TestID_Scan(t *testing.T) {
	u := uuid.New()
	// bytes
	var id ID
	b, _ := u.MarshalBinary()
	assert.NoError(t, id.Scan(b))
	assert.Equal(t, u, uuid.UUID(id))

	// string
	var id2 ID
	assert.NoError(t, id2.Scan(u.String()))
	assert.Equal(t, u, uuid.UUID(id2))

	// invalid bytes
	assert.Error(t, id.Scan([]byte("short")))
	// invalid string
	assert.Error(t, id.Scan("notauuid"))
	// unsupported type
	assert.Error(t, id.Scan(42))
}

func TestID_Value(t *testing.T) {
	id := UUIDToID(uuid.New())
	v, err := id.Value()
	assert.NoError(t, err)
	assert.NotNil(t, v)
}

func TestID_Uint64(t *testing.T) {
	id, _ := NewID()
	assert.NotZero(t, id.Uint64())
}

func TestIDList_StringSlice_FromUUIDList(t *testing.T) {
	u1 := uuid.New()
	u2 := uuid.New()
	list := (IDList{}).FromUUIDList([]uuid.UUID{u1, u2})
	assert.Len(t, list, 2)
	ss := IDList(list).StringSlice()
	assert.Len(t, ss, 2)
	assert.True(t, strings.HasPrefix(ss[0], ""))
}

func TestUUIDListToIDList(t *testing.T) {
	assert.Nil(t, UUIDListToIDList(nil))
	ids := []uuid.UUID{uuid.New(), uuid.New()}
	out := UUIDListToIDList(&ids)
	assert.Len(t, out, 2)
}

func TestShortStringN(t *testing.T) {
	assert.Equal(t, "[hi]", shortStringN("hi", 10))
	assert.Equal(t, "[he]", shortStringN("hello", 2))
}

type validish struct {
	valid bool
	name  string
}

func (v validish) IsValid() bool { return v.valid }
func (v validish) String() string {
	return v.name
}

func TestToStringSlice(t *testing.T) {
	in := []validish{{true, "a"}, {false, "skip"}, {true, "b"}}
	out := ToStringSlice(in)
	assert.Equal(t, []string{"a", "b"}, out)
}

func TestFromStringSliceAndParsePrefixes(t *testing.T) {
	// Valid prefixes, blanks ignored.
	prefs, err := ParsePrefixes([]string{"10.0.0.0/8", "", "  ", "192.168.1.0/24"})
	assert.NoError(t, err)
	assert.Len(t, prefs, 2)

	// Invalid
	_, err = ParsePrefixes([]string{"badinput"})
	assert.Error(t, err)
}

func TestParseAddrPorts(t *testing.T) {
	ports, err := ParseAddrPorts([]string{"10.0.0.1:80"})
	assert.NoError(t, err)
	assert.Len(t, ports, 1)
	_, err = ParseAddrPorts([]string{"bad"})
	assert.Error(t, err)
}

func TestSliceMap(t *testing.T) {
	// nil returns nil
	var nilIn []int
	out, err := SliceMap(nilIn, func(i int) (int, error) { return i, nil })
	assert.NoError(t, err)
	assert.Nil(t, out)

	out, err = SliceMap([]int{1, 2, 3}, func(i int) (int, error) { return i * 2, nil })
	assert.NoError(t, err)
	assert.Equal(t, []int{2, 4, 6}, out)

	// Error propagates
	_, err = SliceMap([]int{1}, func(i int) (int, error) { return 0, assertErrTypes{} })
	assert.Error(t, err)
}

type assertErrTypes struct{}

func (assertErrTypes) Error() string { return "e" }

func TestSliceFilter(t *testing.T) {
	out := SliceFilter([]int{1, 2, 3, 4}, func(v int) bool { return v%2 == 0 })
	assert.Equal(t, []int{2, 4}, out)
}

func TestNilID_Sanity(t *testing.T) {
	// NilID should be the zero id.
	assert.True(t, NilID.IsNil())
	assert.Equal(t, uuid.Nil.String(), NilID.String())
}

func TestParsePrefixesHappyPath(t *testing.T) {
	p, err := netip.ParsePrefix("10.0.0.0/8")
	assert.NoError(t, err)
	assert.Equal(t, "10.0.0.0/8", p.String())
}
