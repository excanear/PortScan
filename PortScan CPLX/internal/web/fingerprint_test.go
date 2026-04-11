package web

import (
	"net/http"
	"testing"
)

func TestFingerprintResponse_Cloudflare(t *testing.T) {
	hdr := make(http.Header)
	hdr.Set("CF-RAY", "abc")
	hdr.Set("Server", "cloudflare")

	fp := FingerprintResponse(hdr, nil, 200)
	if fp.CDN != "cloudflare" {
		t.Fatalf("expected CDN cloudflare, got %q", fp.CDN)
	}
	if fp.WAF != "cloudflare" {
		t.Fatalf("expected WAF cloudflare, got %q", fp.WAF)
	}
	if fp.WAFConfidence < 80 {
		t.Fatalf("expected high WAF confidence, got %d", fp.WAFConfidence)
	}
}

func TestFingerprintResponse_ServerHeader(t *testing.T) {
	hdr := make(http.Header)
	hdr.Set("Server", "nginx/1.18")
	fp := FingerprintResponse(hdr, nil, 200)
	if fp.Server != "nginx" {
		t.Fatalf("expected server nginx, got %q", fp.Server)
	}
}
