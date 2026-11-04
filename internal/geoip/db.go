package geoip

import (
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

type Manager struct {
	mu     sync.RWMutex
	reader *maxminddb.Reader
	dbPath string
}

func NewManager(dbPath string) *Manager {
	mgr := &Manager{dbPath: dbPath}
	if dbPath != "" {
		_ = mgr.LoadDB(dbPath)
	}
	return mgr
}

func (m *Manager) LoadDB(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := os.Stat(path); err != nil {
		return err
	}
	r, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	if m.reader != nil {
		m.reader.Close()
	}
	m.reader = r
	m.dbPath = path
	return nil
}

type mmdbRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		IsoCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
	Traits                       struct {
		AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
		AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
	} `maxminddb:"traits"`
}

func (m *Manager) Lookup(ipStr string) *GeoLocation {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	// 1. 优先内置特征匹配 (RFC 1918 / CGNAT / Loopback)
	if loc, matched := MatchBuiltinRule(ip); matched {
		return loc
	}

	if m == nil {
		return &GeoLocation{
			Country: "公网节点",
		}
	}

	// 2. 本地 MMDB 检索
	m.mu.RLock()
	reader := m.reader
	m.mu.RUnlock()

	if reader != nil {
		var record mmdbRecord
		if err := reader.Lookup(ip, &record); err == nil {
			loc := &GeoLocation{}
			if name, ok := record.Country.Names["zh-CN"]; ok {
				loc.Country = name
			} else if name, ok := record.Country.Names["en"]; ok {
				loc.Country = name
			} else if record.Country.IsoCode != "" {
				loc.Country = record.Country.IsoCode
			}

			if len(record.Subdivisions) > 0 {
				if name, ok := record.Subdivisions[0].Names["zh-CN"]; ok {
					loc.Region = name
				} else if name, ok := record.Subdivisions[0].Names["en"]; ok {
					loc.Region = name
				}
			}

			if name, ok := record.City.Names["zh-CN"]; ok {
				loc.City = name
			} else if name, ok := record.City.Names["en"]; ok {
				loc.City = name
			}

			asn := record.AutonomousSystemNumber
			if asn == 0 {
				asn = record.Traits.AutonomousSystemNumber
			}
			if asn > 0 {
				loc.ASN = fmt.Sprintf("AS%d", asn)
			}

			org := record.AutonomousSystemOrganization
			if org == "" {
				org = record.Traits.AutonomousSystemOrganization
			}
			if org != "" {
				loc.Org = org
			}

			if loc.Country != "" || loc.City != "" || loc.ASN != "" {
				return loc
			}
		}
	}

	// 3. 兜底未匹配
	return &GeoLocation{
		Country: "公网节点",
	}
}

func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reader != nil {
		m.reader.Close()
		m.reader = nil
	}
}
