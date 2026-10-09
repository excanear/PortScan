package scanner

import (
	"context"
	"time"

	"portscan/internal/web"
)

// Config contains scanner configuration values.
type Config struct {
	Target    string
	Ports     []int
	Threads   int
	Timeout   time.Duration
	Verbose   bool
	JSON      bool
	Retries   int // number of retries after first attempt
	RateLimit int // connections per second, 0 = unlimited
}

// PortResult represents the outcome for a single port.
type PortResult struct {
	Port          int                 `json:"port"`
	Open          bool                `json:"open"`
	Protocol      string              `json:"protocol,omitempty"`
	Status        int                 `json:"status,omitempty"`
	Server        string              `json:"server,omitempty"`
	CDN           string              `json:"cdn,omitempty"`
	WAF           string              `json:"waf,omitempty"`
	Technologies  []string            `json:"technologies,omitempty"`
	Filtered      bool                `json:"filtered,omitempty"`
	WAFReason     string              `json:"waf_reason,omitempty"`
	WAFConfidence int                 `json:"waf_confidence,omitempty"`
	Title         string              `json:"title,omitempty"`
	Size          int64               `json:"size,omitempty"`
	Headers       map[string][]string `json:"headers,omitempty"`
	Error         string              `json:"error,omitempty"`
	TLSVersion    string              `json:"tls_version,omitempty"`
	CipherSuite   string              `json:"cipher_suite,omitempty"`
	ALPN          []string            `json:"alpn,omitempty"`
	Certs         []web.CertInfo      `json:"certs,omitempty"`
}

// Scanner is the high-level scanner instance.
type Scanner struct {
	cfg Config
}

// NewScanner creates a new scanner with the provided configuration.
func NewScanner(cfg Config) *Scanner {
	return &Scanner{cfg: cfg}
}

// Start performs the scan and returns results.
// It sets sensible defaults and delegates to the worker pool implementation.
func (s *Scanner) Start(ctx context.Context) ([]PortResult, error) {
	if s.cfg.Threads <= 0 {
		s.cfg.Threads = 100
	}
	if s.cfg.Timeout <= 0 {
		s.cfg.Timeout = 2 * time.Second
	}
	return s.runWorkerPool(ctx)
}
