package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
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
	default:
		return v.String()
	}
}

func (v VulnType) titleColor() string {
	switch v {
	case VulnSQLi, VulnNuclei:
		return colorRed + colorBold
	case VulnXSS:
		return colorYellow + colorBold
	case VulnHeader, VulnCookie:
		return colorYellow + colorBold
	}
	return colorWhite
}

func (v VulnType) rowColor() string {
	switch v {
	case VulnSQLi, VulnNuclei:
		return colorRed
	case VulnXSS:
		return colorYellow
	case VulnHeader, VulnCookie:
		return colorDim
	}
	return colorWhite
}

func (v VulnType) borderColor() string {
	switch v {
	case VulnSQLi, VulnNuclei:
		return colorRed
	case VulnXSS:
		return colorYellow
	case VulnHeader, VulnCookie:
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
	done        chan struct{}
	lineCount   int
}

func NewStatusBar() *StatusBar {
	return &StatusBar{
		startTime:   time.Now(),
		phaseStart:  time.Now(),
		lastSecTime: time.Now(),
		done:        make(chan struct{}),
	}
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
}

func (sb *StatusBar) Tick(reqs int64) {
	atomic.AddInt64(&sb.scanned, 1)
	newTotal := atomic.AddInt64(&sb.reqCount, reqs)
	sb.mu.Lock()
	elapsed := time.Since(sb.lastSecTime).Seconds()
	if elapsed >= 0.5 {
		delta := newTotal - sb.lastSecReqs
		sb.currentRPS = float64(delta) / elapsed
		sb.lastSecReqs = newTotal
		sb.lastSecTime = time.Now()
	}
	sb.mu.Unlock()
}

func (sb *StatusBar) Start() {
	sb.active = true
	fmt.Print(hideCursor)
	go func() {
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-sb.done:
				return
			case <-ticker.C:
				sb.render()
			}
		}
	}()
}

func (sb *StatusBar) Stop() {
	if !sb.active {
		return
	}
	sb.active = false
	close(sb.done)
	sb.mu.Lock()
	lc := sb.lineCount
	sb.lineCount = 0
	sb.mu.Unlock()
	clearN(lc)
	fmt.Print(showCursor)
}

func clearN(n int) {
	for i := 0; i < n; i++ {
		fmt.Print(clearLine + cursorHome)
		if i < n-1 {
			fmt.Print(cursorUp)
		}
	}
}

func (sb *StatusBar) render() {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	phase := sb.phase
	scanned := atomic.LoadInt64(&sb.scanned)
	total := sb.total
	rps := sb.currentRPS
	elapsed := time.Since(sb.startTime).Round(time.Second)
	phaseElapsed := time.Since(sb.phaseStart).Round(time.Second)

	var progress float64
	if total > 0 {
		progress = float64(scanned) / float64(total)
		if progress > 1 {
			progress = 1
		}
	}

	barWidth := 28
	filled := int(float64(barWidth) * progress)
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	var eta string
	if rps > 0 && total > 0 && scanned < total {
		remaining := float64(total-scanned) / rps
		etaDur := time.Duration(remaining) * time.Second
		eta = fmt.Sprintf(" ETA %s", etaDur.Round(time.Second))
	}

	line1 := fmt.Sprintf(" %s%s%s  %s[%d/%d]%s  %s%.1f rps%s  %s⏱ %s%s  %s⚡ %s%s%s",
		colorCyan+colorBold, phase, colorReset,
		colorGreen, scanned, total, colorReset,
		colorYellow, rps, colorReset,
		colorDim, elapsed, colorReset,
		colorBlue, phaseElapsed, eta, colorReset,
	)
	progressLine := fmt.Sprintf(" %s%s%s  %s%.0f%%%s",
		colorCyan, bar, colorReset,
		colorBold, progress*100, colorReset,
	)
	divider := colorDim + strings.Repeat("─", 90) + colorReset

	if sb.lineCount > 0 {
		clearN(sb.lineCount)
	}
	fmt.Print(divider + "\n" + line1 + "\n" + progressLine)
	sb.lineCount = 3
}

func (sb *StatusBar) Log(format string, args ...interface{}) {
	sb.mu.Lock()
	lc := sb.lineCount
	sb.lineCount = 0
	sb.mu.Unlock()

	clearN(lc)
	fmt.Printf(format, args...)
}

type ReportCollector struct {
	mu       sync.Mutex
	findings []Finding
	sitemap  []string
	seenSM   map[string]bool
}

func NewReportCollector() *ReportCollector {
	return &ReportCollector{seenSM: map[string]bool{}}
}

func (r *ReportCollector) AddFinding(f Finding) {
	r.mu.Lock()
	r.findings = append(r.findings, f)
	r.mu.Unlock()
}

func (r *ReportCollector) AddSitemapURL(u string) {
	r.mu.Lock()
	if !r.seenSM[u] {
		r.seenSM[u] = true
		r.sitemap = append(r.sitemap, u)
	}
	r.mu.Unlock()
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
	for _, vt := range []VulnType{VulnSQLi, VulnXSS, VulnNuclei, VulnHeader, VulnCookie} {
		fs, ok := byType[vt]
		if !ok {
			continue
		}
		out.WriteString(renderTable(vt, fs, toTerm))
		out.WriteString("\n")
	}
	return out.String()
}

func renderTable(vt VulnType, findings []Finding, toTerm bool) string {
	var sb strings.Builder

	title := vt.SectionTitle(len(findings))
	if toTerm {
		sb.WriteString("\n" + vt.titleColor() + title + colorReset + "\n")
	} else {
		sb.WriteString("\n" + title + "\n")
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
		if toTerm && (vt == VulnHeader || vt == VulnCookie) {
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
		sb.WriteString("\n" + colorBold + colorCyan + line + colorReset + "\n")
		sb.WriteString(colorBold + colorCyan + "  SCAN SUMMARY" + colorReset + "\n")
		sb.WriteString(colorDim + line + colorReset + "\n")
	} else {
		sb.WriteString("\n" + line + "\n  SCAN SUMMARY\n" + line + "\n")
	}

	total := 0
	vulnTotal := 0
	warningTotal := 0
	infoTotal := 0
	for _, vt := range []VulnType{VulnSQLi, VulnXSS, VulnNuclei, VulnHeader, VulnCookie} {
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
