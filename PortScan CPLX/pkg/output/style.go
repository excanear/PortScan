package output

import "fmt"

// Minimal ANSI-based styling to avoid external dependency in builds.
type Style struct {
	code string
	bold bool
}

func (s Style) Render(in string) string {
	prefix := ""
	if s.bold {
		prefix = "1;"
	}
	return fmt.Sprintf("\x1b[%s%sm%s\x1b[0m", prefix, s.code, in)
}

type BoxStyleType struct{}

func (BoxStyleType) Render(in string) string {
	// simple boxed render
	return fmt.Sprintf("┌─ %s ─┐", in)
}

var (
	HeaderStyle  = Style{code: "96", bold: true}  // bright cyan
	InfoStyle    = Style{code: "37", bold: false} // white/gray
	OpenStyle    = Style{code: "32", bold: true}  // green
	ClosedStyle  = Style{code: "31", bold: true}  // red
	ProtoStyle   = Style{code: "33", bold: false} // yellow
	ServerStyle  = Style{code: "33", bold: true}  // yellow bold
	TitleStyle   = Style{code: "97", bold: false} // bright white
	VerboseStyle = Style{code: "90", bold: false} // dim gray
	BoxStyle     = BoxStyleType{}
)
