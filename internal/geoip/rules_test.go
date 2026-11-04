package geoip

import (
	"net"
	"strings"
	"testing"
)

func TestMatchBuiltinRule(t *testing.T) {
	tests := []struct {
		ip       string
		wantType string
	}{
		{"127.0.0.1", "回环地址"},
		{"192.168.1.1", "局域网"},
		{"10.0.0.1", "局域网"},
		{"100.64.0.1", "城域网"},
		{"172.20.1.1", "局域网"},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		loc, matched := MatchBuiltinRule(ip)
		if !matched {
			t.Fatalf("expected %s to match builtin rule", tt.ip)
		}
		if loc.City == "" && loc.Country == "" {
			t.Fatalf("expected location info for %s", tt.ip)
		}
	}

	// Test public IP should not match
	publicIP := net.ParseIP("8.8.8.8")
	if loc, matched := MatchBuiltinRule(publicIP); matched {
		t.Fatalf("expected public IP 8.8.8.8 not to match builtin rule, got %v", loc)
	}

	// Test nil IP
	if loc, matched := MatchBuiltinRule(nil); matched {
		t.Fatalf("expected nil IP not to match builtin rule, got %v", loc)
	}
}

func TestGeoLocationString(t *testing.T) {
	var nilLoc *GeoLocation
	if nilLoc.String() != "未知位置" {
		t.Errorf("expected 未知位置, got %s", nilLoc.String())
	}

	emptyLoc := &GeoLocation{}
	if emptyLoc.String() != "公网节点" {
		t.Errorf("expected 公网节点, got %s", emptyLoc.String())
	}

	loc := &GeoLocation{
		Country: "中国",
		Region:  "广东",
		City:    "深圳",
		ASN:     "AS4134",
		Org:     "CHINANET",
	}
	s := loc.String()
	if !strings.Contains(s, "中国 广东 深圳") || !strings.Contains(s, "(AS4134 CHINANET)") {
		t.Errorf("unexpected string output: %s", s)
	}
}
