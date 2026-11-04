package probe

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestMeasureTargetLocalServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	tgt := NewTarget("TestServer", ts.URL, u.Host)

	snap, err := MeasureTarget(tgt, "")
	if err != nil {
		t.Fatalf("measure target failed: %v", err)
	}
	if snap.TTFB < 5*time.Millisecond {
		t.Fatalf("expected TTFB >= 5ms, got %v", snap.TTFB)
	}
	if snap.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", snap.StatusCode)
	}
	if snap.TCP <= 0 {
		t.Logf("TCP handshake duration: %v", snap.TCP)
	}
}

func TestMeasureTargetTLSServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("secure ok"))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	tgt := NewTarget("TestTLSServer", ts.URL, u.Host)

	snap, err := MeasureTarget(tgt, "")
	if err != nil {
		t.Fatalf("measure TLS target failed: %v", err)
	}
	if snap.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", snap.StatusCode)
	}
	if snap.TLS <= 0 {
		t.Fatalf("expected TLS handshake > 0, got %v", snap.TLS)
	}
	if snap.TotalHandshake() <= 0 {
		t.Fatalf("expected TotalHandshake > 0, got %v", snap.TotalHandshake())
	}
}

func TestMeasureTargetMethodFallback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fallback ok"))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	tgt := NewTarget("FallbackServer", ts.URL, u.Host)

	snap, err := MeasureTarget(tgt, "")
	if err != nil {
		t.Fatalf("measure fallback target failed: %v", err)
	}
	if snap.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 after GET fallback, got %d", snap.StatusCode)
	}
}

func TestMeasureTargetConnectionError(t *testing.T) {
	// Connect to non-existent server port on 127.0.0.1
	tgt := NewTarget("DeadServer", "http://127.0.0.1:54321", "127.0.0.1:54321")

	snap, err := MeasureTarget(tgt, "")
	if err == nil {
		t.Fatalf("expected error connecting to dead server, got nil")
	}
	if snap == nil {
		t.Fatalf("expected non-nil snap on error")
	}
	if snap.Err == nil {
		t.Fatalf("expected snap.Err to be set")
	}
}

func TestMeasureTargetProxy(t *testing.T) {
	proxyCalled := false
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("proxied"))
	}))
	defer proxyServer.Close()

	tgt := NewTarget("ProxiedTarget", "http://example.com/test", "example.com")
	snap, err := MeasureTarget(tgt, proxyServer.URL)
	if err != nil {
		t.Fatalf("measure target with proxy failed: %v", err)
	}
	if !proxyCalled {
		t.Fatalf("expected proxy server to be called")
	}
	if snap.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", snap.StatusCode)
	}
}
