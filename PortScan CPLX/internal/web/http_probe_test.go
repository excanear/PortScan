package web

import (
	"crypto/tls"
	"testing"
)

func TestTLSHelpers(t *testing.T) {
	if got := tlsVersionString(tls.VersionTLS13); got == "" {
		t.Fatalf("tlsVersionString returned empty for TLS1.3")
	}

	// known mapping exists for TLS_AES_128_GCM_SHA256
	if name := cipherSuiteName(tls.TLS_AES_128_GCM_SHA256); name == "0x0000" || name == "" {
		t.Fatalf("cipherSuiteName did not map known cipher, got %q", name)
	}

	// unknown id should still return a string
	if name := cipherSuiteName(0xdead); name == "" {
		t.Fatalf("cipherSuiteName returned empty for unknown id")
	}
}
