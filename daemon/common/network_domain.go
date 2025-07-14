// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"github.com/cylonix/utils"
	petname "github.com/dustinkirkland/golang-petname"
)

const (
	prefix = "cy"
	baseDomain = ".cylonix.org"
)

func GenrateNetworkDomain() string {
	num := utils.New6DigitCode()
	return prefix + num + baseDomain
}

// GenerateNetworkDomainWithTwoWords generates a domain name using two random
// words. Package petname provides:
// - Adverbs: 42 words
// - Adjectives: 224 words
// - Names: 1295 words
func GenerateNetworkDomainWithTwoWords() string {
    name := petname.Generate(2, "-")
    return name + baseDomain
}

func GenerateNetworkDomainWithThreeWords() string {
    name := petname.Generate(3, "-")
    return name + baseDomain
}
