// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package optional

func Int64(v *int64) int64 {
	if v != nil {
		return *v
	}
	return int64(0)
}

func Int(v *int) int {
	if v != nil {
		return *v
	}
	return 0
}

func AddIntP(a *int, v int) *int {
	n := v + Int(a)
	return &n
}

func AddInt64P(a *int64, v int64) *int64 {
	n := v + Int64(a)
	return &n
}

func AddInt64PIfNotNil(a *int64, v *int64) *int64 {
	if v != nil {
		return AddInt64P(a, *v)
	}
	return a
}

func AddUint64P(a *uint64, v uint64) *uint64 {
	n := v + Uint64(a)
	return &n
}

func AddUint64PIfNotNil(a *uint64, v *uint64) *uint64 {
	if v != nil {
		return AddUint64P(a, *v)
	}
	return a
}

func StringP(s string) *string {
	v := s
	return &v
}

func NilIfEmptyStringP(s string) *string {
	if s == "" {
		return nil
	}
	v := s
	return &v
}

func CopyStringP(s *string) *string {
	if s != nil {
		v := *s
		return &v
	}
	return nil
}

func IntP(n int) *int {
	v := n
	return &v
}

func Int64P(n int64) *int64 {
	v := n
	return &v
}

func Uint(n *uint) uint {
	if n != nil {
		return *n
	}
	return 0
}

func Uint64(n *uint64) uint64 {
	if n != nil {
		return *n
	}
	return 0
}

func Uint64P(n uint64) *uint64 {
	v := n
	return &v
}

func CopyUint64P(n *uint64) *uint64 {
	if n != nil {
		v := *n
		return &v
	}
	return nil
}

func UintPToUint64P(n *uint) *uint64 {
	if n != nil {
		v := uint64(*n)
		return &v
	}
	return nil
}

func Uint64PToUintP(n *uint64) *uint {
	if n != nil {
		v := uint(*n)
		return &v
	}
	return nil
}

func String(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}
func StringSlice(s *[]string) []string {
	if s != nil {
		return *s
	}
	return []string{}
}
func Bool(b *bool) bool {
	if b != nil {
		return *b
	}
	return false
}

func BoolP(b bool) *bool {
	v := b
	return &v
}

func CopyBoolP(b *bool) *bool {
	if b != nil {
		v := *b
		return &v
	}
	return nil
}

func P[T any](v T) *T {
	copy := v
	return &copy
}

func V[T any](p *T, nilV T) T {
	if p == nil {
		return nilV
	}
	return *p
}

func CopyP[T any](v *T) *T {
	if v == nil {
		return nil
	}
	copy := *v
	return &copy
}