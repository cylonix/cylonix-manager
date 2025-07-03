package tools

import (
	"cylonix/sase/pkg/interfaces"
	"cylonix/sase/pkg/logging"
	"cylonix/sase/pkg/logging/logfields"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
)

var (
	logger = logging.DefaultLogger.WithField(logfields.LogSubsys, "global-config")
)

type NetDbNode struct {
	net          *net.IPNet
	providerName string
}
type GlobalConfig struct {
	// TODO: Enhance for i18n
	domainToCategory map[string](string)
	ipNetDb          []NetDbNode
}

func NewGlobalConfig(domainToCategoryFile string, ipAddrDb string) *GlobalConfig {
	domainToCategory := make(map[string](string))

	config := &GlobalConfig{
		domainToCategory: domainToCategory,
		ipNetDb:          make([]NetDbNode, 0),
	}

	logger.Infoln("Loading global configure")
	config.loadDomainToCategoryData(domainToCategoryFile)
	config.loadIPAddrDB(ipAddrDb)

	return config
}

func (config *GlobalConfig) DomainToCategory(domain string) (string, error) {
	if config.domainToCategory == nil {
		return "", errors.New("Domain DB is not initiated.")
	}
	category, ok := config.domainToCategory[domain]
	if ok {
		return category, nil
	}

	return "", fmt.Errorf("cannot find category for %s", domain)

}

func (config *GlobalConfig) loadDomainToCategoryData(confFile string) error {
	file, err := os.Open(confFile)
	if err != nil {
		return errors.New("failed to open file")
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	mMap := make(map[string]([]string))
	err = decoder.Decode(&mMap)
	if err != nil {
		return fmt.Errorf("fail to decoder file: %w", err)
	} else {
		for key, value := range mMap {
			for _, domainName := range value {
				_, ok := config.domainToCategory[domainName]
				if ok {
					logger.Warnf("Duplicate domain in %s/%s", key, domainName)
				} else {
					config.domainToCategory[domainName] = key
				}
			}
		}
	}
	return nil
}

func (config *GlobalConfig) loadIPAddrDB(confFile string) error {
	resources := make([]interfaces.IpAddrScopeData, 0)
	file, err := os.Open(confFile)
	if err != nil {
		return errors.New("failed to open file")
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&resources)
	if err != nil {
		logger.WithError(err).Errorln("fail to decoder file")
		return err
	}

	for _, provider := range resources {
		for _, network := range provider.Networks {
			_, ipnet, err := net.ParseCIDR(network)
			if err != nil {
				logger.WithError(err).Errorln("fail to parse CIDR")
				continue
			}
			node := NetDbNode{providerName: provider.Name, net: ipnet}

			config.ipNetDb = append(config.ipNetDb, node)
		}
	}
	logger.WithField("size", len(config.ipNetDb)).Infoln("IP Net DB loading done.")
	return nil
}

func (config *GlobalConfig) GetProviderNameFromIPAddr(ip string) (string, error) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return "", fmt.Errorf("Failed to parse ip address for %v", ip)
	}

	// It is not a good solution to loop it to find the matching item; enhance it later
	for _, node := range config.ipNetDb {
		if node.net.Contains(addr) {
			return node.providerName, nil
		}
	}
	return "", nil
}
