// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"

	"github.com/cylonix/utils/ipdrawer"
)

func main() {
	fmt.Printf("Testing for ipdrawer openapi function.\n")

	ip, err := ipdrawer.AllocateIPAddr("default", "", "uuid-test-1", nil)
	fmt.Printf("RET: %v - %v\n", ip, err)

	ip, err = ipdrawer.AllocateIPAddr("cylonix", "", "uuid-test-2", nil)
	fmt.Printf("RET: %v - %v\n", ip, err)
}
