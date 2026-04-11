package web

import (
	"net/http"
	"strings"
)

// Fingerprint captures simple heuristic results about the web service.
type Fingerprint struct {
	Server        string   `json:"server,omitempty"`
	CDN           string   `json:"cdn,omitempty"`
	WAF           string   `json:"waf,omitempty"`
	WAFReason     string   `json:"waf_reason,omitempty"`
	WAFConfidence int      `json:"waf_confidence,omitempty"`
	Technologies  []string `json:"technologies,omitempty"`
}

// FingerprintResponse inspects headers, body and status to guess server/CDN/WAF.
// It uses header heuristics, body signature matching and suspicious HTTP codes.
func FingerprintResponse(headers http.Header, body []byte, status int) Fingerprint {
	fp := Fingerprint{}
	if headers == nil {
		return fp
	}

	get := func(k string) string { return headers.Get(k) }
	srv := get("Server")
	lsrv := strings.ToLower(srv)

	// Server header analysis
	if srv != "" {
		switch {
		case strings.Contains(lsrv, "nginx"):
			fp.Server = "nginx"
		case strings.Contains(lsrv, "apache"):
			fp.Server = "apache"
		case strings.Contains(lsrv, "microsoft-iis") || strings.Contains(lsrv, "iis"):
			fp.Server = "iis"
		case strings.Contains(lsrv, "caddy"):
			fp.Server = "caddy"
		case strings.Contains(lsrv, "openresty"):
			fp.Server = "openresty"
		case strings.Contains(lsrv, "litespeed"):
			fp.Server = "litespeed"
		default:
			fp.Server = srv
		}
	}

	// CDN & WAF header hints
	if get("CF-RAY") != "" || get("CF-Cache-Status") != "" || strings.Contains(lsrv, "cloudflare") {
		fp.CDN = "cloudflare"
		fp.WAF = "cloudflare"
		fp.WAFConfidence = 90
		fp.WAFReason = "cf-* headers or Server indicates Cloudflare"
	}
	if get("X-Amz-Cf-Id") != "" || strings.Contains(strings.ToLower(get("X-Cache")), "cloudfront") {
		if fp.CDN == "" {
			fp.CDN = "cloudfront"
		}
	}
	// Akamai
	for k := range headers {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-akamai") || strings.Contains(lk, "akamai") {
			if fp.CDN == "" {
				fp.CDN = "akamai"
			}
			break
		}
	}
	// Fastly
	if get("X-Served-By") != "" || strings.Contains(strings.ToLower(get("X-Cache")), "fastly") {
		if fp.CDN == "" {
			fp.CDN = "fastly"
		}
	}
	// Imperva / Incapsula
	if strings.Contains(strings.ToLower(get("X-CDN")), "incapsula") || strings.Contains(strings.ToLower(get("X-CDN")), "imperva") {
		fp.CDN = "imperva"
		fp.WAF = "imperva"
		fp.WAFConfidence = 85
		fp.WAFReason = "X-CDN header"
	}

	// WAF detection via headers and cookies
	if get("X-Sucuri-ID") != "" {
		fp.WAF = "sucuri"
		fp.WAFConfidence = 90
		fp.WAFReason = "X-Sucuri-ID header"
	}
	if get("X-Mod-Security") != "" || get("X-Mod-Sec") != "" {
		fp.WAF = "mod_security"
		fp.WAFConfidence = 80
		fp.WAFReason = "mod_security header"
	}

	// Inspect Set-Cookie for typical WAF cookies
	for _, c := range headers.Values("Set-Cookie") {
		lc := strings.ToLower(c)
		if strings.Contains(lc, "incap_ses") || strings.Contains(lc, "visid_incap") {
			fp.WAF = "imperva"
			if fp.CDN == "" {
				fp.CDN = "imperva"
			}
			fp.WAFConfidence = 90
			fp.WAFReason = "Incapsula cookie"
		}
		if strings.Contains(lc, "__cfduid") {
			fp.CDN = "cloudflare"
			if fp.WAF == "" {
				fp.WAF = "cloudflare"
				fp.WAFConfidence = 85
				fp.WAFReason = "__cfduid cookie"
			}
		}
		if strings.Contains(lc, "ts") || strings.Contains(lc, "bigipserver") {
			// F5 BigIP
			if fp.WAF == "" {
				fp.WAF = "f5_bigip"
				fp.WAFConfidence = 60
				fp.WAFReason = "BIGip/TS cookie"
			}
		}
	}

	// Technologies: X-Powered-By, X-AspNet-Version, X-Generator, Set-Cookie hints
	techs := map[string]struct{}{}
	if xp := get("X-Powered-By"); xp != "" {
		parts := strings.FieldsFunc(xp, func(r rune) bool { return r == ',' || r == ';' })
		for _, p := range parts {
			p = strings.TrimSpace(p)
			lp := strings.ToLower(p)
			switch {
			case strings.Contains(lp, "php"):
				techs["PHP"] = struct{}{}
			case strings.Contains(lp, "asp.net") || strings.Contains(lp, "aspnet"):
				techs["ASP.NET"] = struct{}{}
			case strings.Contains(lp, "express") || strings.Contains(lp, "node"):
				techs["Node.js"] = struct{}{}
			case strings.Contains(lp, "django") || strings.Contains(lp, "wsgi"):
				techs["Python"] = struct{}{}
			default:
				if len(p) > 0 {
					techs[p] = struct{}{}
				}
			}
		}
	}
	if get("X-AspNet-Version") != "" || get("X-AspNetMvc-Version") != "" {
		techs["ASP.NET"] = struct{}{}
	}
	if gen := get("X-Generator"); gen != "" {
		lg := strings.ToLower(gen)
		if strings.Contains(lg, "wordpress") {
			techs["WordPress"] = struct{}{}
		} else {
			techs[gen] = struct{}{}
		}
	}

	// cookie-based hints for technologies
	for _, c := range headers.Values("Set-Cookie") {
		lc := strings.ToLower(c)
		if strings.Contains(lc, "php") || strings.Contains(lc, "phpsessid") {
			techs["PHP"] = struct{}{}
		}
		if strings.Contains(lc, "wordpress") || strings.Contains(lc, "wp-settings") || strings.Contains(lc, "wordpress_logged_in") {
			techs["WordPress"] = struct{}{}
		}
		if strings.Contains(lc, "jsessionid") {
			techs["Java"] = struct{}{}
		}
		if strings.Contains(lc, "asp.net") || strings.Contains(lc, "aspnet_sessionid") || strings.Contains(lc, "aspsessionid") {
			techs["ASP.NET"] = struct{}{}
		}
	}

	// Server header hints for runtime
	if srv != "" {
		if strings.Contains(lsrv, "gunicorn") || strings.Contains(lsrv, "uwsgi") {
			techs["Python"] = struct{}{}
		}
		if strings.Contains(lsrv, "gws") {
			techs["Google Web Server"] = struct{}{}
		}
	}

	// Body-based WAF signatures and challenge pages
	bodyStr := strings.ToLower(string(body))
	if bodyStr != "" {
		if strings.Contains(bodyStr, "attention required") || strings.Contains(bodyStr, "checking your browser before accessing") || strings.Contains(bodyStr, "d/waf") {
			fp.WAF = "cloudflare"
			fp.WAFConfidence = 90
			fp.WAFReason = "challenge page (Cloudflare)"
		}
		if strings.Contains(bodyStr, "incapsula") || strings.Contains(bodyStr, "incap_sess") {
			fp.WAF = "imperva"
			fp.WAFConfidence = 90
			fp.WAFReason = "Incapsula signature in body/cookies"
		}
		if strings.Contains(bodyStr, "sucuri") || strings.Contains(bodyStr, "cloudproxy") {
			fp.WAF = "sucuri"
			fp.WAFConfidence = 90
			fp.WAFReason = "sucuri signature in body"
		}
		if strings.Contains(bodyStr, "request blocked") || strings.Contains(bodyStr, "access denied") || strings.Contains(bodyStr, "forbidden") {
			// generic blocking text
			if fp.WAF == "" {
				fp.WAF = "generic"
				fp.WAFConfidence = 50
				fp.WAFReason = "blocking text in body"
			}
		}
	}

	// Suspicious HTTP status codes often used by WAFs
	suspicious := map[int]struct{}{
		403: {}, 406: {}, 412: {}, 429: {}, 499: {},
		500: {}, 501: {}, 520: {}, 521: {}, 522: {}, 523: {}, 524: {}, 525: {}, 526: {}, 530: {},
	}
	if _, ok := suspicious[status]; ok {
		if fp.WAF == "" {
			fp.WAF = "possible"
			fp.WAFConfidence = 35
			fp.WAFReason = "suspicious HTTP status code"
		} else {
			// increase confidence when status aligns with headers/body
			if fp.WAFConfidence > 0 {
				fp.WAFConfidence += 5
				if fp.WAFConfidence > 100 {
					fp.WAFConfidence = 100
				}
				if fp.WAFReason == "" {
					fp.WAFReason = "suspicious HTTP status code"
				} else {
					fp.WAFReason = fp.WAFReason + "; suspicious HTTP status code"
				}
			}
		}
	}

	for t := range techs {
		fp.Technologies = append(fp.Technologies, t)
	}

	// Signature DB matches (if any)
	if matches := MatchSignatures(headers, body); len(matches) > 0 {
		for _, m := range matches {
			fp.Technologies = append(fp.Technologies, m)
		}
	}

	return fp
}
