package main

import (
	"cylonix/sase/pkg/ipdrawer"
	"fmt"
)

func main() {
	fmt.Printf("Testing for ipdrawer openapi function.\n")

	ip, err := ipdrawer.AllocateIPAddr("default", "", "uuid-test-1", nil)
	fmt.Printf("RET: %v - %v\n", ip, err)

	ip, err = ipdrawer.AllocateIPAddr("cylonix", "", "uuid-test-2", nil)
	fmt.Printf("RET: %v - %v\n", ip, err)
}
