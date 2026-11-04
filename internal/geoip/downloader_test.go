package geoip

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultDBPath(t *testing.T) {
	path := DefaultDBPath()
	if !strings.Contains(path, ".routescan") || !strings.HasSuffix(path, "geoip.mmdb") {
		t.Fatalf("unexpected default path: %s", path)
	}
}

func TestDownloadDatabase_Success(t *testing.T) {
	content := "fake-mmdb-content-for-test"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	}))
	defer ts.Close()

	oldURL := OpenMMDBURL
	OpenMMDBURL = ts.URL
	defer func() { OpenMMDBURL = oldURL }()

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "sub", "test.mmdb")

	err := DownloadDatabase(destPath)
	if err != nil {
		t.Fatalf("unexpected error downloading database: %v", err)
	}

	data, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("failed to read downloaded file: %v", err)
	}
	if string(data) != content {
		t.Fatalf("expected content %q, got %q", content, string(data))
	}

	// Verify temp file does not exist
	if _, err := os.Stat(destPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("expected temp file to be cleaned up")
	}
}

func TestDownloadDatabase_HTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	oldURL := OpenMMDBURL
	OpenMMDBURL = ts.URL
	defer func() { OpenMMDBURL = oldURL }()

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "404.mmdb")

	err := DownloadDatabase(destPath)
	if err == nil {
		t.Fatalf("expected error for 404 response, got nil")
	}

	if _, err := os.Stat(destPath); !os.IsNotExist(err) {
		t.Fatalf("destPath should not exist after failed download")
	}
}

func TestEnsureDatabase_ExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "existing.mmdb")
	if err := os.WriteFile(destPath, []byte("existing"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	mgr := NewManager(destPath)
	defer mgr.Close()

	// Calling EnsureDatabase should attempt to load existing file and not download
	EnsureDatabase(mgr, false)

	if mgr.dbPath != destPath {
		t.Fatalf("expected dbPath %s, got %s", destPath, mgr.dbPath)
	}
}

func TestEnsureDatabase_AutoDownload(t *testing.T) {
	content := "downloaded-data"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	}))
	defer ts.Close()

	oldURL := OpenMMDBURL
	OpenMMDBURL = ts.URL
	defer func() { OpenMMDBURL = oldURL }()

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "auto.mmdb")

	mgr := NewManager(destPath)
	defer mgr.Close()

	EnsureDatabase(mgr, true)

	// Wait for background goroutine to complete download
	var success bool
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(destPath); err == nil && string(data) == content {
			success = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if !success {
		t.Fatalf("timeout waiting for auto download to complete")
	}
}

func TestEnsureDatabase_NoAutoDownload(t *testing.T) {
	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "missing.mmdb")

	mgr := NewManager(destPath)
	defer mgr.Close()

	EnsureDatabase(mgr, false)

	// File should not be downloaded
	if _, err := os.Stat(destPath); !os.IsNotExist(err) {
		t.Fatalf("file should not exist when autoDownload is false")
	}
}

func TestEnsureDatabase_NilManager(t *testing.T) {
	// Should not panic
	EnsureDatabase(nil, false)
	EnsureDatabase(nil, true)
}
