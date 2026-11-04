package geoip

import (
	"os"
	"testing"
)

func TestLookupMMDBRealFile(t *testing.T) {
	dbPath := DefaultDBPath()
	if _, err := os.Stat(dbPath); err != nil {
		t.Skip("local mmdb not found")
	}
	mgr := NewManager(dbPath)
	defer mgr.Close()

	locGoogle := mgr.Lookup("8.8.8.8")
	t.Logf("8.8.8.8 location: %s", locGoogle.String())

	locCF := mgr.Lookup("104.18.0.1")
	t.Logf("104.18.0.1 location: %s", locCF.String())
}

func TestLookupBuiltinFallback(t *testing.T) {
	mgr := NewManager("") // 无 mmdb 路径
	defer mgr.Close()

	loc := mgr.Lookup("192.168.1.1")
	if loc == nil || loc.Country != "[局域网]" {
		t.Fatalf("expected builtin match, got %+v", loc)
	}

	locPublic := mgr.Lookup("1.1.1.1")
	if locPublic == nil || locPublic.Country != "公网节点" {
		t.Fatalf("expected fallback location, got %+v", locPublic)
	}

	locInvalid := mgr.Lookup("not-an-ip")
	if locInvalid != nil {
		t.Fatalf("expected nil for invalid IP, got %+v", locInvalid)
	}
}

func TestLoadDBNonExistent(t *testing.T) {
	mgr := NewManager("non_existent_file.mmdb")
	defer mgr.Close()

	err := mgr.LoadDB("non_existent_file.mmdb")
	if err == nil {
		t.Fatalf("expected error loading non-existent db, got nil")
	}
}

func TestNilManager(t *testing.T) {
	var mgr *Manager
	loc := mgr.Lookup("127.0.0.1")
	if loc == nil || loc.Country != "[本机]" {
		t.Fatalf("expected loopback, got %+v", loc)
	}

	locPublic := mgr.Lookup("8.8.8.8")
	if locPublic == nil || locPublic.Country != "公网节点" {
		t.Fatalf("expected fallback for nil manager, got %+v", locPublic)
	}

	mgr.Close() // Should not panic
}

