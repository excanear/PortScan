package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"webscan/internal/scanner"
)

// FormatText renders a human-friendly text report with colors and summary.
func FormatText(results []scanner.PortResult, verbose bool, target string, duration time.Duration) string {
	var sb strings.Builder

	// Header
	sb.WriteString(HeaderStyle.Render("WebScan") + "\n")

	// Summary
	openCount := 0
	for _, r := range results {
		if r.Open {
			openCount++
		}
	}
	info := fmt.Sprintf("Target: %s  Ports: %d  Open: %d  Time: %s", target, len(results), openCount, duration.Round(time.Millisecond))
	sb.WriteString(InfoStyle.Render(info) + "\n\n")

	// Results
	for _, r := range results {
		if r.Open {
			statusStyled := OpenStyle.Render("[OPEN]")
			proto := strings.ToUpper(r.Protocol)
			if proto == "" {
				proto = "-"
			}
			protoStyled := ProtoStyle.Render(proto)
			server := r.Server
			if server == "" {
				server = "-"
			}
			serverStyled := ServerStyle.Render(server)
			title := r.Title
			if title == "" {
				title = "-"
			}
			titleStyled := TitleStyle.Render(title)
			sb.WriteString(fmt.Sprintf("%s %3d %s %s  Title: %s\n", statusStyled, r.Port, protoStyled, serverStyled, titleStyled))

			if verbose {
				sb.WriteString(VerboseStyle.Render(fmt.Sprintf("  Status: %d  Size: %d", r.Status, r.Size)) + "\n")
				if r.CDN != "" || r.WAF != "" || len(r.Technologies) > 0 {
					sb.WriteString(VerboseStyle.Render("  Fingerprint:") + "\n")
					if r.Server != "" {
						sb.WriteString(VerboseStyle.Render(fmt.Sprintf("    Server: %s", r.Server)) + "\n")
					}
					if r.CDN != "" {
						sb.WriteString(VerboseStyle.Render(fmt.Sprintf("    CDN: %s", r.CDN)) + "\n")
					}
					if r.WAF != "" {
						sb.WriteString(VerboseStyle.Render(fmt.Sprintf("    WAF: %s", r.WAF)) + "\n")
					}
					if r.WAFReason != "" {
						sb.WriteString(VerboseStyle.Render(fmt.Sprintf("    WAF reason: %s", r.WAFReason)) + "\n")
					}
					if r.WAFConfidence != 0 {
						sb.WriteString(VerboseStyle.Render(fmt.Sprintf("    WAF confidence: %d", r.WAFConfidence)) + "\n")
					}
					if len(r.Technologies) > 0 {
						sb.WriteString(VerboseStyle.Render(fmt.Sprintf("    Technologies: %s", strings.Join(r.Technologies, ", "))) + "\n")
					}
				}
				if len(r.Headers) > 0 {
					sb.WriteString(VerboseStyle.Render("  Headers:") + "\n")
					for k, v := range r.Headers {
						sb.WriteString(VerboseStyle.Render(fmt.Sprintf("    %s: %s", k, strings.Join(v, "; "))) + "\n")
					}
				}
			}
		} else {
			if r.Filtered {
				statusStyled := ProtoStyle.Render("[FILTERED]")
				sb.WriteString(fmt.Sprintf("%s %3d  %s\n", statusStyled, r.Port, InfoStyle.Render(r.Error)))
			} else {
				statusStyled := ClosedStyle.Render("[CLOSED]")
				errMsg := r.Error
				if errMsg == "" {
					errMsg = "closed"
				}
				sb.WriteString(fmt.Sprintf("%s %3d  %s\n", statusStyled, r.Port, InfoStyle.Render(errMsg)))
			}
		}
	}

	sb.WriteString("\n")
	summary := fmt.Sprintf("Scanned %d ports — %d open — %s", len(results), openCount, duration.Round(time.Millisecond))
	sb.WriteString(BoxStyle.Render(InfoStyle.Render(summary)) + "\n")

	return sb.String()
}

// JSONOutput is the top-level structure for JSON output including metadata.
type JSONOutput struct {
	Target       string               `json:"target"`
	PortsScanned int                  `json:"ports_scanned"`
	OpenCount    int                  `json:"open_count"`
	Duration     string               `json:"duration"`
	Results      []scanner.PortResult `json:"results"`
}

// FormatJSON returns indented JSON including a summary of the scan.
func FormatJSON(results []scanner.PortResult, target string, duration time.Duration) ([]byte, error) {
	open := 0
	for _, r := range results {
		if r.Open {
			open++
		}
	}
	out := JSONOutput{
		Target:       target,
		PortsScanned: len(results),
		OpenCount:    open,
		Duration:     duration.String(),
		Results:      results,
	}
	return json.MarshalIndent(out, "", "  ")
}
