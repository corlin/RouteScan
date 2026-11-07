package probe

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"
)

// attemptTiming owns one request's callbacks. httptrace may invoke them from
// multiple goroutines, including simultaneous IPv4/IPv6 connection attempts.
type attemptTiming struct {
	mu                          sync.Mutex
	started, dnsStart, tlsStart time.Time
	connections                 map[string]time.Time
	result                      TimingResult
}

func (t *attemptTiming) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			t.mu.Lock()
			defer t.mu.Unlock()
			t.dnsStart = time.Now()
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			t.mu.Lock()
			defer t.mu.Unlock()
			if !t.dnsStart.IsZero() {
				t.result.DNS = time.Since(t.dnsStart)
			}
		},
		ConnectStart: func(network, addr string) {
			t.mu.Lock()
			defer t.mu.Unlock()
			t.connections[network+" "+addr] = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			t.mu.Lock()
			defer t.mu.Unlock()
			key := network + " " + addr
			if start, ok := t.connections[key]; ok && err == nil && t.result.TCP == 0 {
				t.result.TCP = time.Since(start)
			}
			delete(t.connections, key)
		},
		TLSHandshakeStart: func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			t.tlsStart = time.Now()
		},
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			t.mu.Lock()
			defer t.mu.Unlock()
			if !t.tlsStart.IsZero() {
				t.result.TLS = time.Since(t.tlsStart)
			}
		},
		GotFirstResponseByte: func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.result.TTFB == 0 {
				t.result.TTFB = time.Since(t.started)
			}
		},
	}
}

func measureAttempt(ctx context.Context, client *http.Client, method, rawURL string, target Target) (*ProbeSnapshot, *http.Response, error) {
	timing := &attemptTiming{started: time.Now(), connections: make(map[string]time.Time)}
	snap := &ProbeSnapshot{Target: target, Timestamp: timing.started}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, timing.trace()), method, rawURL, nil)
	if err != nil {
		snap.Err = err
		return snap, nil, err
	}
	req.Header.Set("User-Agent", "RouteScan/1.0 (CCIE Network Inspector)")
	resp, err := client.Do(req)
	// Cancelled dials may finish after client.Do returns.
	timing.mu.Lock()
	snap.DNS, snap.TCP = timing.result.DNS, timing.result.TCP
	snap.TLS, snap.TTFB = timing.result.TLS, timing.result.TTFB
	timing.mu.Unlock()
	snap.Err = err
	if resp != nil {
		snap.StatusCode = resp.StatusCode
	}
	return snap, resp, err
}

// MeasureTarget captures each HTTP phase without mixing HEAD and GET attempts.
func MeasureTarget(target Target, proxyURL string) (*ProbeSnapshot, error) {
	target.IsProxy = proxyURL != ""
	rawURL := target.URL
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	insecure := false
	if u, err := url.Parse(rawURL); err == nil {
		h := u.Hostname()
		insecure = h == "127.0.0.1" || h == "localhost" || h == "::1"
	}
	transport := &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}}
	defer transport.CloseIdleConnections()
	if proxyURL != "" {
		pURL, err := url.Parse(proxyURL)
		if err != nil {
			return &ProbeSnapshot{Target: target, Timestamp: time.Now(), Err: err}, err
		}
		transport.Proxy = http.ProxyURL(pURL)
	}
	client := &http.Client{Transport: transport, Timeout: 6 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	snap, resp, err := measureAttempt(ctx, client, http.MethodHead, rawURL, target)
	if (err != nil || (resp != nil && resp.StatusCode == http.StatusMethodNotAllowed)) && ctx.Err() == nil {
		if resp != nil {
			resp.Body.Close()
		}
		snap, resp, err = measureAttempt(ctx, client, http.MethodGet, rawURL, target)
	}
	if resp != nil {
		resp.Body.Close()
	} // TTFB is complete; no GET body download is needed.
	return snap, err
}
