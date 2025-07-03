package interfaces

type GlobalConfigInterface interface {
	DomainToCategory(domain string) (string, error)
	GetProviderNameFromIPAddr(ip string) (string, error)
}

type IpAddrScopeData struct {
	Name     string   `json:"name"`
	Networks []string `json:"networks"`
}
