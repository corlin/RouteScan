package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"
)

// MeasureTarget performs microsecond-level network timing probing against target
// using net/http/httptrace to capture DNS resolution, TCP handshake, TLS handshake,
// and Time To First Byte (TTFB). It supports optional proxy routing.
func MeasureTarget(target Target, proxyURL string) (*ProbeSnapshot, error) {
	snap := &ProbeSnapshot{
		Target:    target,
		Timestamp: time.Now(),
	}

	var dnsStart, dnsDone time.Time
	var connStart, connDone time.Time
	var tlsStart, tlsDone time.Time
	var firstByteDone time.Time

	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			dnsDone = time.Now()
		},
		ConnectStart: func(network, addr string) {
			connStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			connDone = time.Now()
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			tlsDone = time.Now()
		},
		GotFirstResponseByte: func() {
			firstByteDone = time.Now()
		},
	}

	rawURL := target.URL
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	insecure := false
	if u, err := url.Parse(rawURL); err == nil {
		h := u.Hostname()
		if h == "127.0.0.1" || h == "localhost" || h == "::1" {
			insecure = true
		}
	}

	transport := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure},
	}

	if proxyURL != "" {
		if pURL, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(pURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   6 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodHead, rawURL, nil)
	if err != nil {
		req, err = http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, rawURL, nil)
		if err != nil {
			snap.Err = err
			return snap, err
		}
	}
	req.Header.Set("User-Agent", "RouteScan/1.0 (CCIE Network Inspector)")

	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil || (resp != nil && resp.StatusCode == http.StatusMethodNotAllowed) {
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		// 某些端点 HEAD 被 405 拒绝或断开连接，回退尝试 GET
		reqGet, errGet := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, rawURL, nil)
		if errGet == nil {
			reqGet.Header.Set("User-Agent", "RouteScan/1.0 (CCIE Network Inspector)")
			t0 = time.Now()
			resp, err = client.Do(reqGet)
		}
	}

	if err != nil {
		snap.Err = err
		// 尽可能保留已完成阶段的时延
		if !dnsStart.IsZero() && !dnsDone.IsZero() {
			snap.DNS = dnsDone.Sub(dnsStart)
		}
		if !connStart.IsZero() && !connDone.IsZero() {
			snap.TCP = connDone.Sub(connStart)
		}
		if !tlsStart.IsZero() && !tlsDone.IsZero() {
			snap.TLS = tlsDone.Sub(tlsStart)
		}
		return snap, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	snap.StatusCode = resp.StatusCode

	if !dnsStart.IsZero() && !dnsDone.IsZero() {
		snap.DNS = dnsDone.Sub(dnsStart)
	}
	if !connStart.IsZero() && !connDone.IsZero() {
		snap.TCP = connDone.Sub(connStart)
	}
	if !tlsStart.IsZero() && !tlsDone.IsZero() {
		snap.TLS = tlsDone.Sub(tlsStart)
	}
	if !firstByteDone.IsZero() {
		snap.TTFB = firstByteDone.Sub(t0)
	} else {
		snap.TTFB = time.Since(t0)
	}

	return snap, nil
}
