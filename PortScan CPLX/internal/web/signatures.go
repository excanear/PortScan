package web

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// Signature describes a simple fingerprint rule set loaded from JSON.
type Signature struct {
	Name           string            `json:"name"`
	HeaderContains map[string]string `json:"header_contains,omitempty"`
	BodyContains   []string          `json:"body_contains,omitempty"`
}

var signatureDB []Signature = []Signature{
	{Name: "WordPress", BodyContains: []string{"wp-content", "wp-includes"}},
	{Name: "Joomla", BodyContains: []string{"content=\"Joomla"}},
	{Name: "Cloudflare", HeaderContains: map[string]string{"Server": "cloudflare"}},
}

// LoadSignatures attempts to load additional signatures from a JSON file.
// If the file cannot be read, the embedded defaults remain in use.
func LoadSignatures(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}
	var s []Signature
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	// append to in-memory DB
	signatureDB = append(signatureDB, s...)
	return nil
}

// MatchSignatures returns names of matching signatures for given headers/body.
func MatchSignatures(headers http.Header, body []byte) []string {
	var found []string
	bstr := strings.ToLower(string(body))
	for _, sig := range signatureDB {
		ok := true
		// header checks
		for hk, hv := range sig.HeaderContains {
			if strings.Contains(strings.ToLower(headers.Get(hk)), strings.ToLower(hv)) == false {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		// body checks
		for _, bc := range sig.BodyContains {
			if !strings.Contains(bstr, strings.ToLower(bc)) {
				ok = false
				break
			}
		}
		if ok {
			found = append(found, sig.Name)
		}
	}
	return found
}
