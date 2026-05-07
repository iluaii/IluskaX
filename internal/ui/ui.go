package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"IluskaX/internal/events"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[38;5;196m"
	colorGreen  = "\033[38;5;46m"
	colorYellow = "\033[38;5;226m"
	colorBlue   = "\033[38;5;39m"
	colorCyan   = "\033[38;5;51m"
	colorWhite  = "\033[38;5;15m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"

	clearLine  = "\033[2K"
	cursorUp   = "\033[1A"
	cursorHome = "\r"
	hideCursor = "\033[?25l"
	showCursor = "\033[?25h"
)

const MaxURLLen = 70
const maxPayloadLen = 60

func Red(s string) string    { return colorRed + colorBold + s + colorReset }
func Green(s string) string  { return colorGreen + colorBold + s + colorReset }
func Yellow(s string) string { return colorYellow + s + colorReset }
func Cyan(s string) string   { return colorCyan + s + colorReset }
func Dim(s string) string    { return colorDim + s + colorReset }

func RestoreTerminal(out io.Writer) {
	if out == nil {
		out = os.Stdout
	}
	fmt.Fprint(out, showCursor+colorReset+clearLine+cursorHome)
}

func Truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max-3]) + "..."
}

func stripANSI(s string) string {
	var b strings.Builder
	inEsc := false
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func visibleLen(s string) int {
	return len([]rune(stripANSI(s)))
}

func padRight(s string, width int) string {
	vl := visibleLen(s)
	if vl >= width {
		return s
	}
	return s + strings.Repeat(" ", width-vl)
}

type VulnType int

const (
	VulnSQLi VulnType = iota
	VulnXSS
	VulnHeader
	VulnCookie
	VulnNuclei
	VulnJS
	VulnGraphQL
	VulnRedirect
	VulnExposure
	VulnReflection
)

func (v VulnType) String() string {
	switch v {
	case VulnSQLi:
		return "SQLi"
	case VulnXSS:
		return "XSS"
	case VulnHeader:
		return "Header"
	case VulnCookie:
		return "Cookie"
	case VulnNuclei:
		return "Nuclei"
	case VulnJS:
		return "JS"
	case VulnGraphQL:
		return "GraphQL"
	case VulnRedirect:
		return "Open Redirect"
	case VulnExposure:
		return "Exposure"
	case VulnReflection:
		return "Reflection"
	}
	return "Unknown"
}

type FindingLevel int

const (
	LevelInfo FindingLevel = iota
	LevelWarning
	LevelVulnerability
)

func (l FindingLevel) String() string {
	switch l {
	case LevelInfo:
		return "info"
	case LevelWarning:
		return "warning"
	case LevelVulnerability:
		return "vulnerability"
	}
	return "unknown"
}

func (l FindingLevel) color() string {
	switch l {
	case LevelInfo:
		return colorCyan
	case LevelWarning:
		return colorYellow
	case LevelVulnerability:
		return colorRed
	}
	return colorWhite
}

func (v VulnType) SectionTitle(count int) string {
	switch v {
	case VulnHeader:
		return fmt.Sprintf(" ◈ %s FINDINGS (%d found) ", v.String(), count)
	case VulnCookie:
		return fmt.Sprintf(" ◈ %s ISSUES (%d found) ", v.String(), count)
	case VulnJS:
		return fmt.Sprintf(" ◈ %s SIGNATURES (%d found) ", v.String(), count)
	case VulnGraphQL:
		return fmt.Sprintf(" ◈ %s FINDINGS (%d found) ", v.String(), count)
	case VulnRedirect:
		return fmt.Sprintf(" ◈ %s FINDINGS (%d found) ", v.String(), count)
	case VulnExposure:
		return fmt.Sprintf(" ◈ %s FINDINGS (%d found) ", v.String(), count)
	case VulnReflection:
		return fmt.Sprintf(" ◈ %s MAP (%d found) ", v.String(), count)
	default:
		return fmt.Sprintf(" ◈ %s VULNERABILITIES (%d found) ", v.String(), count)
	}
}

func (v VulnType) SummaryLabel() string {
	switch v {
	case VulnHeader:
		return "Header findings"
	case VulnCookie:
		return "Cookie issues"
	case VulnJS:
		return "JS signatures"
	case VulnGraphQL:
		return "GraphQL findings"
	case VulnRedirect:
		return "Open redirects"
	case VulnExposure:
		return "Exposure findings"
	case VulnReflection:
		return "Reflected params"
	default:
		return v.String()
	}
}

func (v VulnType) titleColor() string {
	switch v {
	case VulnSQLi, VulnNuclei, VulnRedirect:
		return colorRed + colorBold
	case VulnXSS:
		return colorYellow + colorBold
	case VulnHeader, VulnCookie:
		return colorYellow + colorBold
	case VulnJS, VulnExposure, VulnReflection:
		return colorYellow + colorBold
	case VulnGraphQL:
		return colorCyan + colorBold
	}
	return colorWhite
}

func (v VulnType) rowColor() string {
	switch v {
	case VulnSQLi, VulnNuclei, VulnRedirect:
		return colorRed
	case VulnXSS:
		return colorYellow
	case VulnHeader, VulnCookie:
		return colorDim
	case VulnJS, VulnExposure, VulnReflection:
		return colorYellow
	case VulnGraphQL:
		return colorCyan
	}
	return colorWhite
}

func (v VulnType) borderColor() string {
	switch v {
	case VulnSQLi, VulnNuclei, VulnRedirect:
		return colorRed
	case VulnXSS:
		return colorYellow
	case VulnHeader, VulnCookie:
		return colorCyan
	case VulnJS, VulnExposure, VulnReflection:
		return colorYellow
	case VulnGraphQL:
		return colorCyan
	}
	return colorWhite
}

type Finding struct {
	Type     VulnType
	Level    FindingLevel
	URL      string
	Payload  string
	Detail   string
	Severity string
}

type StatusBar struct {
	mu          sync.Mutex
	out         io.Writer
	emitter     *events.Emitter
	silent      bool
	partialLog  string
	phase       string
	scanned     int64
	total       int64
	reqCount    int64
	startTime   time.Time
	phaseStart  time.Time
	lastSecReqs int64
	lastSecTime time.Time
	currentRPS  float64
	active      bool
}

func NewStatusBar() *StatusBar {
	return NewStatusBarWithEmitter(os.Stdout, nil)
}

func NewStatusBarWithEmitter(out io.Writer, emitter *events.Emitter) *StatusBar {
	if out == nil {
		out = os.Stdout
	}
	return &StatusBar{
		out:         out,
		emitter:     emitter,
		startTime:   time.Now(),
		phaseStart:  time.Now(),
		lastSecTime: time.Now(),
	}
}

func (sb *StatusBar) SetSilent(silent bool) {
	sb.mu.Lock()
	sb.silent = silent
	sb.mu.Unlock()
}

func (sb *StatusBar) SetPhase(name string, total int64) {
	sb.mu.Lock()
	sb.phase = name
	sb.total = total
	atomic.StoreInt64(&sb.scanned, 0)
	atomic.StoreInt64(&sb.reqCount, 0)
	sb.phaseStart = time.Now()
	sb.lastSecReqs = 0
	sb.lastSecTime = time.Now()
	sb.currentRPS = 0
	sb.mu.Unlock()
	if sb.emitter != nil {
		sb.emitter.Publish(events.Event{
			Type:    events.EventPhaseStarted,
			Source:  "status_bar",
			Phase:   name,
			Scanned: 0,
			Total:   total,
		})
	}
}

func (sb *StatusBar) Tick(reqs int64) {
	scanned := atomic.AddInt64(&sb.scanned, 1)
	newTotal := atomic.AddInt64(&sb.reqCount, reqs)
	total := atomic.LoadInt64(&sb.total)
	phase := ""
	sb.mu.Lock()
	elapsed := time.Since(sb.lastSecTime).Seconds()
	if elapsed >= 0.5 {
		delta := newTotal - sb.lastSecReqs
		sb.currentRPS = float64(delta) / elapsed
		sb.lastSecReqs = newTotal
		sb.lastSecTime = time.Now()
	}
	phase = sb.phase
	sb.mu.Unlock()
	if sb.emitter != nil {
		sb.emitter.Publish(events.Event{
			Type:    events.EventPhaseProgress,
			Source:  "status_bar",
			Phase:   phase,
			Scanned: scanned,
			Total:   total,
		})
	}
}

func (sb *StatusBar) Start() {
	sb.active = true
}

func (sb *StatusBar) Stop() {
	sb.active = false
	if sb.partialLog != "" {
		fmt.Fprintln(sb.out, sb.partialLog)
		sb.partialLog = ""
	}
}

type statusWriter struct {
	sb *StatusBar
}

func NewStatusWriter(sb *StatusBar) io.Writer {
	return &statusWriter{sb: sb}
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w == nil || w.sb == nil {
		return len(p), nil
	}
	w.sb.writeLogChunk(string(p))
	return len(p), nil
}

func (sb *StatusBar) Log(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	sb.writeLogChunk(msg)
}

func (sb *StatusBar) writeLogChunk(chunk string) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	normalized := strings.ReplaceAll(chunk, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	joined := sb.partialLog + normalized
	lines := strings.Split(joined, "\n")

	if strings.HasSuffix(joined, "\n") {
		sb.partialLog = ""
		if len(lines) > 0 {
			lines = lines[:len(lines)-1]
		}
	} else {
		sb.partialLog = lines[len(lines)-1]
		lines = lines[:len(lines)-1]
	}

	if len(lines) == 0 {
		return
	}

	msg := strings.Join(lines, "\n")
	if msg != "" {
		msg += "\n"
	}

	if !sb.silent {
		fmt.Fprint(sb.out, msg)
	}
	if sb.emitter != nil && strings.TrimSpace(stripANSI(msg)) != "" {
		sb.emitter.Publish(events.Event{
			Type:    events.EventLogMessage,
			Source:  "status_bar",
			Message: msg,
		})
	}
}

type ReportCollector struct {
	mu       sync.Mutex
	emitter  *events.Emitter
	findings []Finding
	seenFind map[string]bool
	sitemap  []string
	seenSM   map[string]bool
}

func NewReportCollector() *ReportCollector {
	return NewReportCollectorWithEmitter(nil)
}

func NewReportCollectorWithEmitter(emitter *events.Emitter) *ReportCollector {
	return &ReportCollector{
		emitter:  emitter,
		seenFind: map[string]bool{},
		seenSM:   map[string]bool{},
	}
}

func (r *ReportCollector) AddFinding(f Finding) {
	r.mu.Lock()
	if r.seenFind == nil {
		r.seenFind = map[string]bool{}
	}
	key := strings.ToLower(strings.Join([]string{
		f.Type.String(),
		f.Level.String(),
		strings.TrimSpace(f.URL),
		strings.TrimSpace(f.Payload),
		strings.TrimSpace(f.Detail),
		strings.TrimSpace(f.Severity),
	}, "\x00"))
	if r.seenFind[key] {
		r.mu.Unlock()
		return
	}
	r.seenFind[key] = true
	r.findings = append(r.findings, f)
	r.mu.Unlock()
	if r.emitter != nil {
		r.emitter.Publish(events.Event{
			Type:    events.EventFindingAdded,
			Source:  "report_collector",
			Message: f.Type.String(),
			Payload: map[string]string{
				"type":     f.Type.String(),
				"level":    f.Level.String(),
				"url":      f.URL,
				"payload":  f.Payload,
				"detail":   f.Detail,
				"severity": f.Severity,
			},
		})
	}
}

func (r *ReportCollector) AddSitemapURL(u string) {
	r.mu.Lock()
	added := false
	if !r.seenSM[u] {
		r.seenSM[u] = true
		r.sitemap = append(r.sitemap, u)
		added = true
	}
	r.mu.Unlock()
	if added && r.emitter != nil {
		r.emitter.Publish(events.Event{
			Type:    events.EventSitemapAdded,
			Source:  "report_collector",
			Message: u,
			Payload: map[string]string{"url": u},
		})
	}
}

func (r *ReportCollector) Findings() []Finding {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Finding, len(r.findings))
	copy(out, r.findings)
	return out
}

func (r *ReportCollector) Sitemap() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.sitemap))
	copy(out, r.sitemap)
	return out
}

func PrintFindingsTable(findings []Finding, toTerm bool) string {
	if len(findings) == 0 {
		return ""
	}
	byType := map[VulnType][]Finding{}
	for _, f := range findings {
		byType[f.Type] = append(byType[f.Type], f)
	}
	var out strings.Builder
	wroteSection := false
	for _, vt := range []VulnType{VulnSQLi, VulnXSS, VulnNuclei, VulnRedirect, VulnReflection, VulnExposure, VulnHeader, VulnCookie, VulnJS, VulnGraphQL} {
		fs, ok := byType[vt]
		if !ok {
			continue
		}
		if wroteSection {
			out.WriteString("\n")
		}
		out.WriteString(renderTable(vt, fs, toTerm))
		wroteSection = true
	}
	return out.String()
}

func renderTable(vt VulnType, findings []Finding, toTerm bool) string {
	var sb strings.Builder

	title := vt.SectionTitle(len(findings))
	if toTerm {
		sb.WriteString(vt.titleColor() + title + colorReset + "\n")
	} else {
		sb.WriteString(title + "\n")
	}

	hasDetail := vt != VulnHeader && vt != VulnCookie
	colURL := 40
	colPayload := 45
	colDetail := 18
	if !hasDetail {
		colURL = 38
		colPayload = 55
	}
	if !toTerm {
		colURL = visibleLen("URL")
		colPayload = visibleLen("Payload")
		if !hasDetail {
			colPayload = visibleLen("Issue")
		}
		if hasDetail {
			colDetail = visibleLen("Detail")
		}
		for _, f := range findings {
			if l := visibleLen(stripANSI(f.URL)); l > colURL {
				colURL = l
			}
			if l := visibleLen(stripANSI(f.Payload)); l > colPayload {
				colPayload = l
			}
			if hasDetail {
				if l := visibleLen(stripANSI(f.Detail)); l > colDetail {
					colDetail = l
				}
			}
		}
	}

	makeSep := func(l, m, r, fill string) string {
		s := l + strings.Repeat(fill, colURL+2) + m + strings.Repeat(fill, colPayload+2)
		if hasDetail {
			s += m + strings.Repeat(fill, colDetail+2)
		}
		return s + r
	}
	topSep := makeSep("┌", "┬", "┐", "─")
	midSep := makeSep("├", "┼", "┤", "─")
	botSep := makeSep("└", "┴", "┘", "─")

	bc := ""
	if toTerm {
		bc = vt.borderColor()
	}

	writeBorder := func(line string) {
		if toTerm {
			sb.WriteString(bc + line + colorReset + "\n")
		} else {
			sb.WriteString(line + "\n")
		}
	}

	payloadHeader := "Payload"
	if !hasDetail {
		payloadHeader = "Issue"
	}

	hURL := padRight("URL", colURL)
	hPay := padRight(payloadHeader, colPayload)
	hDet := padRight("Detail", colDetail)

	writeBorder(topSep)

	if toTerm {
		sb.WriteString(bc + "│" + colorReset + " " + colorBold + hURL + colorReset + " " +
			bc + "│" + colorReset + " " + colorBold + hPay + colorReset + " " +
			bc + "│" + colorReset)
		if hasDetail {
			sb.WriteString(" " + colorBold + hDet + colorReset + " " + bc + "│" + colorReset)
		}
		sb.WriteString("\n")
	} else {
		row := "│ " + hURL + " │ " + hPay + " │"
		if hasDetail {
			row += " " + hDet + " │"
		}
		sb.WriteString(row + "\n")
	}

	writeBorder(midSep)

	rc := vt.rowColor()
	for _, f := range findings {
		cleanURL := stripANSI(f.URL)
		cleanPayload := stripANSI(f.Payload)
		cleanDetail := stripANSI(f.Detail)

		uStr := cleanURL
		pStr := cleanPayload
		if toTerm {
			uStr = Truncate(cleanURL, colURL)
			pStr = Truncate(cleanPayload, colPayload)
		}
		uCell := padRight(uStr, colURL)
		pCell := padRight(pStr, colPayload)

		rowColor := rc
		if toTerm && (vt == VulnHeader || vt == VulnCookie || vt == VulnJS || vt == VulnGraphQL || vt == VulnExposure || vt == VulnReflection) {
			rowColor = f.Level.color()
		}

		if toTerm {
			sb.WriteString(bc + "│" + colorReset + " " + rowColor + uCell + colorReset + " " +
				bc + "│" + colorReset + " " + rowColor + pCell + colorReset + " " +
				bc + "│" + colorReset)
			if hasDetail {
				dStr := Truncate(cleanDetail, colDetail)
				dCell := padRight(dStr, colDetail)
				sb.WriteString(" " + rowColor + dCell + colorReset + " " + bc + "│" + colorReset)
			}
			sb.WriteString("\n")
		} else {
			uCell = padRight(cleanURL, colURL)
			pCell = padRight(cleanPayload, colPayload)
			row := "│ " + uCell + " │ " + pCell + " │"
			if hasDetail {
				dCell := padRight(cleanDetail, colDetail)
				row += " " + dCell + " │"
			}
			sb.WriteString(row + "\n")
		}
	}

	writeBorder(botSep)
	return sb.String()
}

func PrintSummary(findings []Finding, startTime time.Time, toTerm bool) string {
	var sb strings.Builder
	elapsed := time.Since(startTime).Round(time.Second)

	counts := map[VulnType]int{}
	for _, f := range findings {
		counts[f.Type]++
	}

	width := 60
	line := strings.Repeat("═", width)

	if toTerm {
		sb.WriteString(colorBold + colorCyan + line + colorReset + "\n")
		sb.WriteString(colorBold + colorCyan + "  SCAN SUMMARY" + colorReset + "\n")
		sb.WriteString(colorDim + line + colorReset + "\n")
	} else {
		sb.WriteString(line + "\n  SCAN SUMMARY\n" + line + "\n")
	}

	total := 0
	vulnTotal := 0
	warningTotal := 0
	infoTotal := 0
	for _, vt := range []VulnType{VulnSQLi, VulnXSS, VulnNuclei, VulnRedirect, VulnReflection, VulnExposure, VulnHeader, VulnCookie, VulnJS, VulnGraphQL} {
		if n := counts[vt]; n > 0 {
			total += n
			label := fmt.Sprintf("  %-16s : %d", vt.SummaryLabel(), n)
			if toTerm {
				sb.WriteString(vt.titleColor() + label + colorReset + "\n")
			} else {
				sb.WriteString(label + "\n")
			}
		}
	}

	for _, f := range findings {
		switch f.Level {
		case LevelVulnerability:
			vulnTotal++
		case LevelWarning:
			warningTotal++
		case LevelInfo:
			infoTotal++
		}
	}

	if vulnTotal == 0 {
		status := "  No vulnerabilities found"
		if toTerm {
			sb.WriteString(Green(status) + "\n")
		} else {
			sb.WriteString(status + "\n")
		}
	} else {
		status := fmt.Sprintf("  Total vulnerabilities: %d", vulnTotal)
		if toTerm {
			sb.WriteString(Red(status) + "\n")
		} else {
			sb.WriteString(status + "\n")
		}
	}

	if total > vulnTotal {
		extra := fmt.Sprintf("  Additional findings/issues: %d", total-vulnTotal)
		if toTerm {
			sb.WriteString(Yellow(extra) + "\n")
		} else {
			sb.WriteString(extra + "\n")
		}
	}

	if warningTotal > 0 {
		line := fmt.Sprintf("  Warnings: %d", warningTotal)
		if toTerm {
			sb.WriteString(Yellow(line) + "\n")
		} else {
			sb.WriteString(line + "\n")
		}
	}

	if infoTotal > 0 {
		line := fmt.Sprintf("  Info findings: %d", infoTotal)
		if toTerm {
			sb.WriteString(Cyan(line) + "\n")
		} else {
			sb.WriteString(line + "\n")
		}
	}

	timeStr := fmt.Sprintf("  Elapsed: %s", elapsed)
	if toTerm {
		sb.WriteString(Dim(timeStr) + "\n")
		sb.WriteString(colorDim + line + colorReset + "\n")
	} else {
		sb.WriteString(timeStr + "\n" + line + "\n")
	}
	return sb.String()
}

func PrintSitemap(urls []string, toTerm bool) string {
	if len(urls) == 0 {
		return ""
	}
	var sb strings.Builder
	title := fmt.Sprintf("\n SITEMAP (%d URLs)\n", len(urls))
	line := strings.Repeat("─", 70)

	if toTerm {
		sb.WriteString(colorCyan + colorBold + title + colorReset)
		sb.WriteString(colorDim + line + colorReset + "\n")
	} else {
		sb.WriteString(title + line + "\n")
	}

	for _, u := range urls {
		if toTerm {
			sb.WriteString(colorDim + "  ├─ " + colorReset + Truncate(u, MaxURLLen) + "\n")
		} else {
			sb.WriteString("  ├─ " + u + "\n")
		}
	}

	if toTerm {
		sb.WriteString(colorDim + line + colorReset + "\n")
	} else {
		sb.WriteString(line + "\n")
	}
	return sb.String()
}

func WriteReport(path string, sitemap []string, findings []Finding, startTime time.Time) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	clean := make([]Finding, len(findings))
	for i, fi := range findings {
		clean[i] = Finding{
			Type:     fi.Type,
			Level:    fi.Level,
			URL:      stripANSI(fi.URL),
			Payload:  stripANSI(fi.Payload),
			Detail:   stripANSI(fi.Detail),
			Severity: stripANSI(fi.Severity),
		}
	}

	fmt.Fprint(f, PrintSitemap(sitemap, false))
	fmt.Fprint(f, PrintFindingsTable(clean, false))
	fmt.Fprint(f, PrintSummary(clean, startTime, false))
	return nil
}

func WriteJSONReport(path string, sitemap []string, findings []Finding, startTime time.Time) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	clean := make([]Finding, len(findings))
	for i, fi := range findings {
		clean[i] = Finding{
			Type:     fi.Type,
			Level:    fi.Level,
			URL:      stripANSI(fi.URL),
			Payload:  stripANSI(fi.Payload),
			Detail:   stripANSI(fi.Detail),
			Severity: stripANSI(fi.Severity),
		}
	}

	type jsonFinding struct {
		Type     string `json:"type"`
		Level    string `json:"level"`
		URL      string `json:"url"`
		Payload  string `json:"payload"`
		Detail   string `json:"detail"`
		Severity string `json:"severity"`
	}
	type jsonSummary struct {
		ElapsedSeconds  int64 `json:"elapsed_seconds"`
		TotalFindings   int   `json:"total_findings"`
		Vulnerabilities int   `json:"vulnerabilities"`
		Warnings        int   `json:"warnings"`
		InfoFindings    int   `json:"info_findings"`
	}
	payload := struct {
		Sitemap  []string      `json:"sitemap"`
		Findings []jsonFinding `json:"findings"`
		Summary  jsonSummary   `json:"summary"`
	}{
		Sitemap: sitemap,
	}

	for _, fi := range clean {
		payload.Findings = append(payload.Findings, jsonFinding{
			Type:     fi.Type.String(),
			Level:    fi.Level.String(),
			URL:      fi.URL,
			Payload:  fi.Payload,
			Detail:   fi.Detail,
			Severity: fi.Severity,
		})
		switch fi.Level {
		case LevelVulnerability:
			payload.Summary.Vulnerabilities++
		case LevelWarning:
			payload.Summary.Warnings++
		case LevelInfo:
			payload.Summary.InfoFindings++
		}
	}
	payload.Summary.TotalFindings = len(clean)
	payload.Summary.ElapsedSeconds = int64(time.Since(startTime).Round(time.Second).Seconds())

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}
