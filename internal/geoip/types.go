package geoip

import "fmt"

type GeoLocation struct {
	Country string
	Region  string
	City    string
	ASN     string
	Org     string
}

func (g *GeoLocation) String() string {
	if g == nil {
		return "未知位置"
	}
	geo := ""
	if g.Country != "" {
		geo += g.Country
	}
	if g.Region != "" && g.Region != g.Country {
		if geo != "" {
			geo += " "
		}
		geo += g.Region
	}
	if g.City != "" && g.City != g.Region {
		if geo != "" {
			geo += " "
		}
		geo += g.City
	}
	asInfo := ""
	if g.ASN != "" || g.Org != "" {
		if g.ASN != "" && g.Org != "" {
			asInfo = fmt.Sprintf("(%s %s)", g.ASN, g.Org)
		} else if g.ASN != "" {
			asInfo = fmt.Sprintf("(%s)", g.ASN)
		} else {
			asInfo = fmt.Sprintf("(%s)", g.Org)
		}
	}
	if asInfo != "" {
		if geo != "" {
			return geo + " " + asInfo
		}
		return asInfo
	}
	if geo == "" {
		return "公网节点"
	}
	return geo
}
