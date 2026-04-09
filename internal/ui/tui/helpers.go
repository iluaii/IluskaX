package tui

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

func currentFindingsView(m model) bool {
	if m.inDetail {
		return m.detailTab == detailFindings
	}
	return m.globalTab == tabFindings
}

func filteredFindings(m model) []findingItem {
	out := make([]findingItem, 0, len(m.findings))
	query := strings.ToLower(strings.TrimSpace(m.findingQuery))
	for _, item := range m.findings {
		if !matchesFindingFilter(item, m.findingFilter) {
			continue
		}
		if query != "" {
			hay := strings.ToLower(item.kind + " " + item.url + " " + item.payload + " " + item.detail)
			if !strings.Contains(hay, query) {
				continue
			}
		}
		out = append(out, item)
	}
	return out
}

func matchesFindingFilter(item findingItem, filter findingFilter) bool {
	switch filter {
	case filterVulnerability:
		return item.level == "vulnerability"
	case filterWarning:
		return item.level == "warning"
	case filterInfo:
		return item.level == "info"
	default:
		return true
	}
}

func findingFilterLabel(filter findingFilter) string {
	switch filter {
	case filterVulnerability:
		return "vulnerability"
	case filterWarning:
		return "warning"
	case filterInfo:
		return "info"
	default:
		return "all"
	}
}

func (m model) totalVulns() int {
	total := 0
	for _, scan := range m.scans {
		total += scan.vulnCount
	}
	return total
}

func (m model) totalWarnings() int {
	total := 0
	for _, scan := range m.scans {
		total += scan.warnCount
	}
	return total
}

func (m model) totalInfos() int {
	total := 0
	for _, scan := range m.scans {
		total += scan.infoCount
	}
	return total
}

func groupTargetsByHost(targets []string) map[string][]string {
	grouped := make(map[string][]string)
	for _, raw := range targets {
		host := "unknown"
		label := raw
		if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
			host = parsed.Scheme + "://" + parsed.Host
			label = parsed.RequestURI()
			if label == "" {
				label = "/"
			}
		}
		grouped[host] = append(grouped[host], label)
	}
	return grouped
}

func renderTargetGroups(grouped map[string][]string) []string {
	hosts := make([]string, 0, len(grouped))
	for host := range grouped {
		hosts = append(hosts, host)
	}
	sortStrings(hosts)

	lines := make([]string, 0, len(grouped)*4)
	for _, host := range hosts {
		lines = append(lines, host)
		items := grouped[host]
		sortStrings(items)
		for i, item := range items {
			prefix := "├─ "
			if i == len(items)-1 {
				prefix = "└─ "
			}
			lines = append(lines, prefix+item)
		}
		lines = append(lines, "")
	}
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func renderScanTargetGroups(scans []scanEntry) ([]string, int, int) {
	lines := make([]string, 0, len(scans)*6)
	scanCount := 0
	targetCount := 0

	for _, scan := range scans {
		if len(scan.targets) == 0 {
			continue
		}
		scanCount++
		targetCount += len(scan.targets)
		header := valueOrFallback(scan.target, scan.id) + " [" + strings.ToUpper(scan.status) + "]"
		lines = append(lines, header)

		grouped := groupTargetsByHost(scan.targets)
		groupLines := renderTargetGroups(grouped)
		for _, line := range groupLines {
			if line == "" {
				continue
			}
			lines = append(lines, "  "+line)
		}
		lines = append(lines, "")
	}

	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	return lines, scanCount, targetCount
}

func sortStrings(items []string) {
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j] < items[i] {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
}

func readLogPreview(path string, limit int) []string {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := splitLines(string(data))
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(line, " \t")
		if strings.TrimSpace(line) == "" || isStructuralBlank(line) {
			continue
		}
		out = append(out, line)
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

func parseCrawlPathFromLog(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := stripANSI(strings.TrimSpace(sc.Text()))
		if !strings.Contains(line, "CRAWL COMPLETE:") {
			continue
		}
		parts := strings.SplitN(line, "CRAWL COMPLETE:", 2)
		if len(parts) != 2 {
			continue
		}
		return strings.TrimSpace(parts[1])
	}
	return ""
}

func readCrawlTargets(path string) []string {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]bool)
	var targets []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "POST|") || seen[line] {
			continue
		}
		seen[line] = true
		targets = append(targets, line)
	}
	return targets
}

func (m *model) pushLog(line string) {
	line = strings.TrimRight(line, " \t")
	if strings.TrimSpace(line) == "" {
		return
	}
	if isStructuralBlank(line) {
		return
	}
	m.logs = append(m.logs, line)
	if len(m.logs) > 500 {
		m.logs = m.logs[len(m.logs)-500:]
	}
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Split(s, "\n")
}

func isStructuralBlank(s string) bool {
	replacer := strings.NewReplacer(
		"│", "",
		"├", "",
		"└", "",
		"─", "",
		"╰", "",
		"╭", "",
		"╮", "",
		"╯", "",
		" ", "",
		"\t", "",
	)
	return replacer.Replace(s) == ""
}

func detailTabNames() []string {
	return []string{"Logs", "Findings", "Targets", "Control"}
}

func globalTabNames() []string {
	return []string{"Dashboard", "Findings", "Targets", "History", "New Scan"}
}

func trimLastRune(s string) string {
	runes := []rune(s)
	if len(runes) == 0 {
		return s
	}
	return string(runes[:len(runes)-1])
}

func valueOrDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

func valueOrFallback(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func placeholderValue(v, placeholder string) string {
	if strings.TrimSpace(v) == "" {
		return colorDim + placeholder + colorReset
	}
	return v
}

func sanitizeName(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	replacer := strings.NewReplacer("://", "_", "/", "_", "\\", "_", "?", "_", "&", "_", "=", "_", ":", "_", "|", "_", " ", "_")
	return replacer.Replace(v)
}

func percent(scanned, total int64) int {
	if total <= 0 {
		return 0
	}
	if scanned >= total {
		return 100
	}
	return int((scanned * 100) / total)
}

func shorten(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 3 || len([]rune(s)) <= max {
		return s
	}
	runes := []rune(s)
	return string(runes[:max-3]) + "..."
}

func stripANSI(s string) string {
	var b strings.Builder
	inEscape := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inEscape {
			if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
				inEscape = false
			}
			continue
		}
		if ch == 0x1b {
			inEscape = true
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m model) hasActiveBackgroundScans() bool {
	for i, scan := range m.scans {
		if i == 0 {
			continue
		}
		switch scan.status {
		case "running", "paused", "queued":
			return true
		}
	}
	return false
}

func padViewHeight(view string, height int) string {
	if height <= 0 {
		return view
	}
	lineCount := strings.Count(view, "\n") + 1
	if lineCount >= height {
		return view
	}
	return view + strings.Repeat("\n", height-lineCount)
}

func padLineWidth(line string, width int) string {
	if width <= 0 {
		return line
	}
	visible := len([]rune(stripANSI(line)))
	if visible >= width {
		return line
	}
	return line + strings.Repeat(" ", width-visible)
}

func normalizeView(view string, width, height int) string {
	targetWidth := maxInt(1, width-1)
	lines := splitLines(view)
	for i, line := range lines {
		lines[i] = padLineWidth(truncateANSI(line, targetWidth), targetWidth)
	}
	if height > 0 && len(lines) > height {
		lines = lines[:height]
	}
	if height > 0 && len(lines) < height {
		for len(lines) < height {
			lines = append(lines, strings.Repeat(" ", targetWidth))
		}
	}
	return strings.Join(lines, "\n")
}

func (m model) currentLogLines() []string {
	if scan, ok := m.selectedDetailScan(); ok && m.detailScan != 0 {
		return readLogPreview(scan.reportPath, 5000)
	}
	return m.logs
}

func (m model) logMaxScroll() int {
	height := m.height - 10
	if height < 8 {
		height = 8
	}
	total := len(m.currentLogLines())
	if total <= height {
		return 0
	}
	return total - height
}

func truncateANSI(s string, maxVisible int) string {
	if maxVisible <= 0 {
		return ""
	}
	var out strings.Builder
	visible := 0
	inEscape := false
	hadANSI := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inEscape {
			out.WriteByte(ch)
			if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
				inEscape = false
			}
			continue
		}
		if ch == 0x1b {
			hadANSI = true
			inEscape = true
			out.WriteByte(ch)
			continue
		}
		if visible >= maxVisible {
			break
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			break
		}
		out.WriteRune(r)
		visible++
		i += size - 1
	}
	if hadANSI {
		out.WriteString(colorReset)
	}
	return out.String()
}

func (m *model) setTransientStatus(message string) {
	if m == nil {
		return
	}
	m.statusMessage = message
	m.statusUntil = time.Now().Add(2 * time.Second)
}

func (m *model) setPersistentStatus(message string) {
	if m == nil {
		return
	}
	m.statusMessage = message
	m.statusUntil = time.Time{}
}

func (m *model) requestConfirm(action confirmAction, message string) {
	if m == nil {
		return
	}
	m.confirmAction = action
	m.confirmMessage = message
}

func (m *model) clearConfirm() {
	if m == nil {
		return
	}
	m.confirmAction = confirmNone
	m.confirmMessage = ""
}

func (m *model) refreshCompletionStatus() {
	if m == nil || !m.finished {
		return
	}
	if m.hasActiveBackgroundScans() {
		m.setPersistentStatus("Current pentest session finished. Background scans are still active.")
		return
	}
	m.setPersistentStatus("All scans finished. Press Esc to close TUI.")
}

func isActiveScanStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running", "paused", "queued":
		return true
	default:
		return false
	}
}

func (m model) contextualStatusMessage() string {
	if strings.TrimSpace(m.statusMessage) == "" {
		return ""
	}
	if !m.inDetail {
		msg := strings.TrimSpace(m.statusMessage)
		if strings.HasPrefix(msg, "Current pentest session finished.") || strings.HasPrefix(msg, "All scans finished.") {
			return ""
		}
	}
	if m.inDetail {
		if scan, ok := m.selectedDetailScan(); ok && scan.phase == "external" && isActiveScanStatus(scan.status) {
			return fmt.Sprintf("Selected background scan is still %s.", scan.status)
		}
		return m.statusMessage
	}
	if m.globalTab == tabDashboard {
		selected := m.selectedDashboardScan()
		if selected.phase == "external" && isActiveScanStatus(selected.status) {
			return fmt.Sprintf("Selected background scan is still %s.", selected.status)
		}
	}
	return m.statusMessage
}

func padRightPlain(s string, width int) string {
	visible := len([]rune(stripANSI(s)))
	if visible >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visible)
}

func renderStatusBadge(status string) string {
	label := "[UNKNOWN ]"
	color := colorDim
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running":
		label = "[RUNNING ]"
		color = colorBlue
	case "paused":
		label = "[PAUSED  ]"
		color = colorYellow
	case "finished":
		label = "[FINISHED]"
		color = colorGreen
	case "queued":
		label = "[QUEUED  ]"
		color = colorYellow
	case "failed":
		label = "[FAILED  ]"
		color = colorRed
	case "stopped":
		label = "[STOPPED ]"
		color = colorDim
	}
	return color + colorBold + label + colorReset
}
