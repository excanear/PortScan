package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"webscan/internal/web"
)

// scanPort checks TCP connectivity to a single port using net.Dialer.DialContext,
// supports retries and basic backoff, and classifies closed vs filtered.
func (s *Scanner) scanPort(ctx context.Context, port int, limiter *rate.Limiter) PortResult {
	addr := fmt.Sprintf("%s:%d", s.cfg.Target, port)
	attempts := s.cfg.Retries + 1
	var lastErr error
	r := PortResult{Port: port, Open: false}

	for attempt := 1; attempt <= attempts; attempt++ {
		// honor parent context
		select {
		case <-ctx.Done():
			r.Error = "cancelled"
			return r
		default:
		}

		// rate limiting using token-bucket limiter
		if limiter != nil {
			if err := limiter.Wait(ctx); err != nil {
				r.Error = "cancelled"
				return r
			}
		}

		dialer := &net.Dialer{}
		attemptCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
		conn, err := dialer.DialContext(attemptCtx, "tcp", addr)
		cancel()
		if err == nil {
			conn.Close()
			r.Open = true
			r.Error = ""
			return r
		}

		lastErr = err
		errStr := strings.ToLower(err.Error())
		// classify
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			r.Filtered = true
			r.Error = "timeout"
		} else if strings.Contains(errStr, "refused") {
			r.Filtered = false
			r.Error = "connection refused"
		} else if strings.Contains(errStr, "no route to host") || strings.Contains(errStr, "network is unreachable") {
			r.Error = "unreachable"
		} else if strings.Contains(errStr, "i/o timeout") {
			r.Filtered = true
			r.Error = "timeout"
		} else {
			r.Error = err.Error()
		}

		// if we have more attempts, wait with backoff
		if attempt < attempts {
			backoff := time.Duration(100*(1<<uint(attempt-1))) * time.Millisecond
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				r.Error = "cancelled"
				return r
			}
			continue
		}
	}

	if lastErr != nil && r.Error == "" {
		r.Error = lastErr.Error()
	}
	return r
}

// runWorkerPool runs a pool of workers to concurrently scan ports.
func (s *Scanner) runWorkerPool(ctx context.Context) ([]PortResult, error) {
	numJobs := len(s.cfg.Ports)
	if numJobs == 0 {
		return nil, nil
	}

	jobs := make(chan int, numJobs)
	results := make(chan PortResult, numJobs)
	var wg sync.WaitGroup

	// rate limiter setup (token-bucket)
	var limiter *rate.Limiter
	if s.cfg.RateLimit > 0 {
		burst := s.cfg.RateLimit
		if burst <= 0 {
			burst = 1
		}
		limiter = rate.NewLimiter(rate.Limit(s.cfg.RateLimit), burst)
	}

	worker := func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case port, ok := <-jobs:
				if !ok {
					return
				}
				res := s.scanPort(ctx, port, limiter)
				if res.Open {
					// attempt HTTP/HTTPS probe for additional metadata
					pr, err := web.ProbeHTTP(ctx, s.cfg.Target, port, s.cfg.Timeout)
					if err == nil {
						res.Protocol = pr.Protocol
						res.Status = pr.Status
						// convert headers (http.Header -> map[string][]string)
						hdrs := make(map[string][]string, len(pr.Headers))
						for k, v := range pr.Headers {
							hdrs[k] = v
						}
						res.Headers = hdrs
						res.Title = pr.Title
						res.Size = pr.Size
						res.TLSVersion = pr.TLSVersion
						res.CipherSuite = pr.CipherSuite
						if len(pr.ALPN) > 0 {
							res.ALPN = pr.ALPN
						}
						if len(pr.Certs) > 0 {
							res.Certs = pr.Certs
						}

						// fingerprint based on headers and small body sample
						fp := web.FingerprintResponse(pr.Headers, pr.Body, pr.Status)
						if fp.Server != "" && res.Server == "" {
							res.Server = fp.Server
						}
						if fp.CDN != "" {
							res.CDN = fp.CDN
						}
						if fp.WAF != "" {
							res.WAF = fp.WAF
						}
						if fp.WAFReason != "" {
							res.WAFReason = fp.WAFReason
						}
						if fp.WAFConfidence != 0 {
							res.WAFConfidence = fp.WAFConfidence
						}
						if len(fp.Technologies) > 0 {
							res.Technologies = fp.Technologies
						}
					} else {
						// keep existing Error info but append probe error
						if res.Error == "" {
							res.Error = err.Error()
						} else {
							res.Error = fmt.Sprintf("%s; probe: %s", res.Error, err.Error())
						}
					}
				}

				select {
				case results <- res:
				case <-ctx.Done():
					return
				}
			}
		}
	}

	// Start workers
	workers := s.cfg.Threads
	if workers <= 0 {
		workers = 100
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}

	// Feed jobs
	go func() {
		for _, p := range s.cfg.Ports {
			select {
			case jobs <- p:
			case <-ctx.Done():
				break
			}
		}
		close(jobs)
	}()

	// Collect results
	var collected []PortResult
	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		collected = append(collected, r)
	}

	return collected, nil
}
