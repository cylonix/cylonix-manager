// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package user

import (
	"github.com/cylonix/utils/password"
)

func validatePassword(p string) bool {
	return password.IsValid(p)
}

func generatePassword() (string, error) {
	return password.New()
}