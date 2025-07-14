// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package test

import "fmt"

func ErrNotImplemented(method string) error {
	return fmt.Errorf("method %v is not implemented", method)
}
