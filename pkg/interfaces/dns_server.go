package interfaces

type DNSServer interface {
	AddRecord(hostname, ip, rootDomain string) error
	DelRecord(hostname, ip, rootDomain string) error
}
