package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ProbeResult holds metadata from an HTTP/HTTPS probe.
type ProbeResult struct {
	Port        int
	Protocol    string
	Status      int
	Headers     http.Header
	Title       string
	Size        int64
	Body        []byte
	TLSVersion  string
	CipherSuite string
	ALPN        []string
	Certs       []CertInfo
}

const maxBodySize = 1 << 20 // 1MB

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// CertInfo is a lightweight representation of a peer certificate.
type CertInfo struct {
	Subject    string
	Issuer     string
	NotBefore  time.Time
	NotAfter   time.Time
	Serial     string
	DNSNames   []string
	SigAlg     string
	PubKeyAlgo string
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return "SSL3.0"
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("TLSv0x%04x", v)
	}
}

func cipherSuiteName(id uint16) string {
	// common modern cipher suites; fall back to hex id
	m := map[uint16]string{
		tls.TLS_AES_128_GCM_SHA256:                  "TLS_AES_128_GCM_SHA256",
		tls.TLS_AES_256_GCM_SHA384:                  "TLS_AES_256_GCM_SHA384",
		tls.TLS_CHACHA20_POLY1305_SHA256:            "TLS_CHACHA20_POLY1305_SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	}
	if n, ok := m[id]; ok {
		return n
	}
	return fmt.Sprintf("0x%04x", id)
}

func newHTTPClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext:         (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConnsPerHost: 10,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ProbeHTTP attempts to discover whether an HTTP(S) service is running on the
// provided host:port. It will try HTTP and HTTPS (order heuristic based on port)
// and return status, headers and page title when available.
func ProbeHTTP(ctx context.Context, host string, port int, timeout time.Duration) (ProbeResult, error) {
	schemes := []string{"http", "https"}
	// prefer https for commonly used TLS ports
	if port == 443 || port == 8443 || port == 9443 {
		schemes = []string{"https", "http"}
	}

	client := newHTTPClient(timeout)

	for _, scheme := range schemes {
		urlStr := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
		req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "webscan/0.1")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
			// can't reach with this scheme, try next
			continue
		}

		// If this was an HTTP response that redirects to an https URL,
		// prefer to try the HTTPS probe instead of returning the redirect.
		if scheme == "http" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			if loc != "" {
				if u, err := url.Parse(loc); err == nil {
					if strings.EqualFold(u.Scheme, "https") {
						// consume body (bounded) and continue to next scheme
						io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodySize))
						resp.Body.Close()
						continue
					}
				}
			}
		}

		// read bounded body
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		resp.Body.Close()
		title := ""
		if m := titleRe.FindSubmatch(body); len(m) >= 2 {
			title = strings.TrimSpace(string(m[1]))
		}

		// collect TLS info if present
		var tlsVersion string
		var cipher string
		var alpn []string
		var certs []CertInfo
		if resp.TLS != nil {
			tlsVersion = tlsVersionString(resp.TLS.Version)
			cipher = cipherSuiteName(resp.TLS.CipherSuite)
			if resp.TLS.NegotiatedProtocol != "" {
				alpn = append(alpn, resp.TLS.NegotiatedProtocol)
			}
			for _, c := range resp.TLS.PeerCertificates {
				certs = append(certs, CertInfo{
					Subject:    c.Subject.String(),
					Issuer:     c.Issuer.String(),
					NotBefore:  c.NotBefore,
					NotAfter:   c.NotAfter,
					Serial:     c.SerialNumber.String(),
					DNSNames:   c.DNSNames,
					SigAlg:     c.SignatureAlgorithm.String(),
					PubKeyAlgo: c.PublicKeyAlgorithm.String(),
				})
			}
		}

		// assemble result
		res := ProbeResult{
			Port:        port,
			Protocol:    scheme,
			Status:      resp.StatusCode,
			Headers:     resp.Header,
			Title:       title,
			Size:        int64(len(body)),
			Body:        body,
			TLSVersion:  tlsVersion,
			CipherSuite: cipher,
			ALPN:        alpn,
			Certs:       certs,
		}

		return res, nil
	}

	// If we reach here, no scheme succeeded. Return a generic error.
	return ProbeResult{Port: port, Protocol: "", Status: 0, Headers: http.Header{}}, fmt.Errorf("no HTTP/HTTPS service detected on %s:%d", host, port)
}
