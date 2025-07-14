// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package interfaces

type DNSServer interface {
	AddRecord(hostname, ip, rootDomain string) error
	DelRecord(hostname, ip, rootDomain string) error
}
