package tui

import (
	"fmt"
	"strings"
	"time"
)

func (m model) View() string {
	width := m.width
	if width <= 0 {
		width = 120
	}
	var sb strings.Builder
	sb.WriteString(m.renderHeader(width))
	sb.WriteString("\n")
	if m.inDetail {
		sb.WriteString(m.renderDetailView(width))
	} else {
		sb.WriteString(m.renderGlobalView(width))
	}
	if m.confirmAction != confirmNone && strings.TrimSpace(m.confirmMessage) != "" {
		sb.WriteString("\n" + colorYellow + colorBold + "Confirm: " + m.confirmMessage + " [Enter/Y confirm, Esc/N cancel]" + colorReset)
	} else if msg := m.contextualStatusMessage(); msg != "" && (m.statusUntil.IsZero() || time.Now().Before(m.statusUntil)) {
		sb.WriteString("\n" + colorDim + msg + colorReset)
	}
	sb.WriteString("\n" + m.renderFooter(width))
	return normalizeView(sb.String(), width, m.height)
}

func (m model) renderHeader(width int) string {
	var sb strings.Builder
	title := "IluskaX Control Center"
	if m.inDetail {
		title = "IluskaX Scan Details"
		if scan, ok := m.selectedDetailScan(); ok {
			title += " - " + shorten(scan.target, 32)
		}
	}
	sb.WriteString(colorBold + colorCyan + " " + title + " " + colorReset + "\n")
	sb.WriteString(colorDim + strings.Repeat("─", maxInt(30, width-2)) + colorReset + "\n")
	if m.inDetail {
		sb.WriteString(renderTabs(detailTabNames(), int(m.detailTab)))
	} else {
		sb.WriteString(renderTabs(globalTabNames(), int(m.globalTab)))
	}
	return sb.String()
}

func (m model) renderGlobalView(width int) string {
	switch m.globalTab {
	case tabDashboard:
		return m.renderDashboard(width)
	case tabFindings:
		return m.renderFindings(width, false)
	case tabTargets:
		return m.renderTargets(width, false)
	case tabHistory:
		return m.renderHistory(width)
	case tabNewScan:
		return m.renderNewScan(width)
	default:
		return ""
	}
}

func (m model) renderDetailView(width int) string {
	switch m.detailTab {
	case detailLogs:
		return m.renderLogs(width)
	case detailFindings:
		return m.renderFindings(width, true)
	case detailTargets:
		return m.renderTargets(width, true)
	case detailControl:
		return m.renderControl(width)
	default:
		return ""
	}
}

func (m model) renderDashboard(width int) string {
	var sb strings.Builder
	sb.WriteString(colorBold + " Active Scans" + colorReset + "\n")
	sb.WriteString(colorDim + strings.Repeat("─", maxInt(20, width-2)) + colorReset + "\n")
	if len(m.scans) == 0 {
		sb.WriteString("No scans yet.\n")
	} else {
		for i, scan := range m.scans {
			cursor := "  "
			if i == m.selectedScan {
				cursor = colorBlue + "▸ " + colorReset
			}
			sb.WriteString(cursor + renderScanLine(scan) + "\n")
		}
	}
	sb.WriteString("\n")
	sb.WriteString(colorBold + " Dashboard Summary" + colorReset + "\n")
	selected := m.selectedDashboardScan()
	sb.WriteString(fmt.Sprintf("Overall: running=%d queued=%d scans=%d findings vuln=%d warn=%d info=%d\n",
		countStatus(m.scans, "running"), len(m.queue), len(m.scans), m.totalVulns(), m.totalWarnings(), m.totalInfos()))
	if len(m.scans) > 0 {
		sb.WriteString(fmt.Sprintf("Selected: %s | Status: %s | Phase: %s | Progress: %d%% | Elapsed: %s\n",
			selected.target, renderStatusBadge(selected.status), valueOrDash(selected.phase), selected.percent, elapsedForScan(selected)))
		sb.WriteString(fmt.Sprintf("Selected findings: vuln=%d warn=%d info=%d\n",
			selected.vulnCount, selected.warnCount, selected.infoCount))
	}
	sb.WriteString("\n")
	sb.WriteString(colorBold + " Actions" + colorReset + "\n")
	sb.WriteString("Enter: open selected scan   Tab: switch main tabs   New Scan tab: create another run or queue item\n")
	sb.WriteString(colorDim + "\nOpen the selected scan to inspect logs, findings, targets, or controls." + colorReset + "\n")
	if msg := m.completionBannerMessage(); msg != "" {
		sb.WriteString("\n" + colorGreen + msg + colorReset + "\n")
	}
	return sb.String()
}

func (m model) renderLogs(width int) string {
	var sb strings.Builder
	sb.WriteString(colorBold + " Live Logs" + colorReset + "\n")
	sb.WriteString(colorDim + strings.Repeat("─", maxInt(20, width-2)) + colorReset + "\n")
	logHeight := m.height - 10
	if logHeight < 8 {
		logHeight = 8
	}
	lines := m.currentLogLines()
	totalLines := len(lines)
	if scan, ok := m.selectedDetailScan(); ok && m.detailScan != 0 {
		if len(lines) == 0 {
			sb.WriteString("No log output available yet for this scan.\n")
			if scan.reportPath != "" {
				sb.WriteString(colorDim + "Expected log: " + scan.reportPath + colorReset + "\n")
			}
			return sb.String()
		}
	}
	start := 0
	if len(lines) > logHeight {
		maxScroll := len(lines) - logHeight
		if m.followLogs {
			start = maxScroll
		} else {
			if m.scroll > maxScroll {
				m.scroll = maxScroll
			}
			start = m.scroll
		}
		lines = lines[start : start+logHeight]
	}
	for _, line := range lines {
		sb.WriteString(line + "\n")
	}
	sb.WriteString("\n")
	sb.WriteString(colorDim + fmt.Sprintf("Showing %d/%d log lines", len(lines), totalLines) + colorReset + "\n")
	if scan, ok := m.selectedDetailScan(); ok {
		if scan.status == "running" || scan.status == "paused" {
			sb.WriteString(colorYellow + "Selected background scan is still active." + colorReset + "\n")
		} else if msg := m.completionBannerMessage(); msg != "" {
			sb.WriteString(colorGreen + msg + colorReset + "\n")
		}
	} else if msg := m.completionBannerMessage(); msg != "" {
		sb.WriteString(colorGreen + msg + colorReset + "\n")
	}
	return sb.String()
}

func (m model) renderFindings(width int, detail bool) string {
	var sb strings.Builder
	title := " Findings"
	if detail {
		title = " Scan Findings"
	}
	sb.WriteString(colorBold + title + colorReset + "\n")
	sb.WriteString(colorDim + strings.Repeat("─", maxInt(20, width-2)) + colorReset + "\n")
	if detail && m.detailScan != 0 {
		sb.WriteString("Detailed findings are only available for the active in-process scan right now.\n")
		if scan, ok := m.selectedDetailScan(); ok && scan.reportPath != "" {
			sb.WriteString(colorDim + "Background scan log: " + scan.reportPath + colorReset + "\n")
		}
		return sb.String()
	}
	filterLine := colorDim + fmt.Sprintf("Filter: %s", findingFilterLabel(m.findingFilter)) + colorReset
	if strings.TrimSpace(m.findingQuery) != "" {
		filterLine += colorDim + " | Search: " + m.findingQuery + colorReset
	}
	sb.WriteString(filterLine + "\n")
	lines := findingLines(m, width)
	if len(lines) == 0 {
		sb.WriteString("No findings yet.\n")
		return sb.String()
	}

	maxRows := m.height - 10
	if maxRows < 6 {
		maxRows = 6
	}
	start := 0
	if len(lines) > maxRows {
		maxScroll := len(lines) - maxRows
		if m.scroll > maxScroll {
			m.scroll = maxScroll
		}
		start = m.scroll
	}
	end := minInt(len(lines), start+maxRows)
	for _, line := range lines[start:end] {
		sb.WriteString(line + "\n")
	}
	if len(lines) > maxRows {
		sb.WriteString(colorDim + fmt.Sprintf("Showing %d-%d of %d lines", start+1, end, len(lines)) + colorReset + "\n")
	}
	return sb.String()
}

func (m model) renderTargets(width int, detail bool) string {
	var sb strings.Builder
	title := " Targets"
	if detail {
		title = " Scan Targets"
	}
	sb.WriteString(colorBold + title + colorReset + "\n")
	sb.WriteString(colorDim + strings.Repeat("─", maxInt(20, width-2)) + colorReset + "\n")
	lines := []string(nil)
	footer := ""
	if detail {
		targets := []string(nil)
		if scan, ok := m.selectedDetailScan(); ok {
			targets = scan.targets
		}
		if len(targets) == 0 {
			sb.WriteString("No targets discovered yet.\n")
			return sb.String()
		}
		grouped := groupTargetsByHost(targets)
		lines = renderTargetGroups(grouped)
		footer = fmt.Sprintf("\n%d targets total across %d host(s)", len(targets), len(grouped))
	} else {
		var scanCount, targetCount int
		lines, scanCount, targetCount = renderScanTargetGroups(m.scans)
		if len(lines) == 0 {
			sb.WriteString("No targets discovered yet.\n")
			return sb.String()
		}
		footer = fmt.Sprintf("\n%d targets total across %d scan(s)", targetCount, scanCount)
	}
	maxRows := m.height - 8
	if maxRows < 6 {
		maxRows = 6
	}
	start := 0
	if len(lines) > maxRows {
		maxScroll := len(lines) - maxRows
		if m.scroll > maxScroll {
			m.scroll = maxScroll
		}
		start = m.scroll
	}
	end := minInt(len(lines), start+maxRows)
	for i := start; i < end; i++ {
		sb.WriteString(lines[i] + "\n")
	}
	sb.WriteString(colorDim + footer + colorReset + "\n")
	return sb.String()
}

func (m model) renderHistory(width int) string {
	var sb strings.Builder
	sb.WriteString(colorBold + " History" + colorReset + "\n")
	sb.WriteString(colorDim + strings.Repeat("─", maxInt(20, width-2)) + colorReset + "\n")
	if len(m.history) == 0 && len(m.queue) == 0 {
		sb.WriteString("No history yet.\n")
		sb.WriteString(colorDim + "\nPress x to clear persisted history." + colorReset + "\n")
		return sb.String()
	}
	for _, item := range m.history {
		if !isMeaningfulHistoryItem(item) {
			continue
		}
		sb.WriteString(fmt.Sprintf("%s  %s\n", renderStatusBadge(item.status), item.target))
		sb.WriteString("  " + item.command + "\n")
		if item.logPath != "" {
			sb.WriteString("  " + colorDim + item.logPath + colorReset + "\n")
		}
	}
	if len(m.queue) > 0 {
		sb.WriteString("\n" + colorBold + " Queue" + colorReset + "\n")
		for _, item := range m.queue {
			sb.WriteString(fmt.Sprintf("%s  %s\n", renderStatusBadge("queued"), item.target))
			sb.WriteString("  " + item.command + "\n")
		}
	}
	sb.WriteString(colorDim + "\nPress x to clear persisted history." + colorReset + "\n")
	return sb.String()
}

func (m model) renderNewScan(width int) string {
	var sb strings.Builder
	sb.WriteString(colorBold + " New Scan" + colorReset + "\n")
	sb.WriteString(colorDim + strings.Repeat("─", maxInt(20, width-2)) + colorReset + "\n")
	sb.WriteString("Prepare a new scan from the dashboard.\n\n")
	sb.WriteString(renderInput("Target URL", m.launchHost, m.focus == focusHost))
	sb.WriteString(renderInput("Flags", m.launchFlags, m.focus == focusFlags))
	sb.WriteString(renderActionSelector(m.action, m.focus == focusAction))
	sb.WriteString("\n")
	cmd := "./luska -u " + placeholderValue(m.launchHost, "<target>")
	if strings.TrimSpace(m.launchFlags) != "" {
		cmd += " " + strings.TrimSpace(m.launchFlags)
	}
	sb.WriteString(colorBold + "Command Preview" + colorReset + "\n")
	sb.WriteString(colorDim + cmd + colorReset + "\n\n")
	sb.WriteString("Enter: next field / execute action   Left/Right: switch action\n")
	return sb.String()
}

func (m model) renderControl(width int) string {
	var sb strings.Builder
	current := scanEntry{target: "-", status: "-", phase: "-"}
	if scan, ok := m.selectedDetailScan(); ok {
		current = scan
	}
	sb.WriteString(colorBold + " Scan Control" + colorReset + "\n")
	sb.WriteString(colorDim + strings.Repeat("─", maxInt(20, width-2)) + colorReset + "\n")
	sb.WriteString(fmt.Sprintf("Target: %s\n", current.target))
	sb.WriteString(fmt.Sprintf("Status: %s\n", renderStatusBadge(current.status)))
	sb.WriteString(fmt.Sprintf("Phase: %s\n", valueOrDash(current.phase)))
	sb.WriteString(fmt.Sprintf("Progress: %d%% (%d/%d)\n", current.percent, current.scanned, current.total))
	sb.WriteString(fmt.Sprintf("Elapsed: %s\n", elapsedForScan(current)))
	if current.reportPath != "" {
		sb.WriteString(fmt.Sprintf("Output: %s\n", current.reportPath))
	}
	sb.WriteString("\n")
	if current.phase == "external" && current.target != "-" {
		pauseLabel := "Pause"
		if current.status == "paused" {
			pauseLabel = "Resume"
		}
		sb.WriteString(colorBold + "Actions" + colorReset + "\n")
		sb.WriteString(renderControlButton("P", pauseLabel, colorYellow))
		sb.WriteString("  ")
		sb.WriteString(renderControlButton("R", "Restart", colorBlue))
		sb.WriteString("  ")
		sb.WriteString(renderControlButton("S", "Stop", colorRed))
		sb.WriteString("\n")
		sb.WriteString(colorDim + "Use the hotkeys above for the selected background scan." + colorReset + "\n")
		sb.WriteString("Esc: return to the global dashboard\n")
	} else {
		sb.WriteString("Pause, restart, and stop are available for background scans launched from the TUI.\n")
		sb.WriteString("Use Esc to return to the global dashboard and launch or queue more scans.\n")
	}
	return sb.String()
}

func renderTabs(names []string, active int) string {
	var sb strings.Builder
	for i, name := range names {
		if i == active {
			sb.WriteString(colorBlue + colorBold + "[ " + name + " ]" + colorReset + " ")
		} else {
			sb.WriteString(colorDim + name + colorReset + " ")
		}
	}
	return sb.String()
}

func renderInput(label, value string, active bool) string {
	border := colorDim
	if active {
		border = colorBlue
	}
	return fmt.Sprintf("%s%s:%s %s%s%s\n", colorBold, label, colorReset, border, placeholderValue(value, "..."), colorReset)
}

func renderActionSelector(mode actionMode, active bool) string {
	left := "Run now"
	right := "Queue"
	if mode == actionRunNow {
		left = colorGreen + colorBold + "[ Run now ]" + colorReset
		right = colorDim + "Queue" + colorReset
	} else {
		left = colorDim + "Run now" + colorReset
		right = colorYellow + colorBold + "[ Queue ]" + colorReset
	}
	if active {
		return colorBlue + colorBold + "▸ Action:" + colorReset + " " + left + "  " + right + "\n"
	}
	return "Action: " + left + "  " + right + "\n"
}

func renderScanLine(scan scanEntry) string {
	target := padRightPlain(shorten(scan.target, 18), 18)
	phase := padRightPlain(shorten(valueOrDash(scan.phase), 18), 18)
	return fmt.Sprintf("%s  %s  %s  %3d%%  vuln=%d warn=%d info=%d",
		target,
		renderStatusBadge(scan.status),
		phase,
		scan.percent,
		scan.vulnCount,
		scan.warnCount,
		scan.infoCount,
	)
}

func (m model) completionBannerMessage() string {
	if !m.finished || m.hasActiveBackgroundScans() {
		return ""
	}
	return "All scans finished. Press Esc to close TUI."
}

func (m model) renderFooter(width int) string {
	line := strings.Repeat("─", maxInt(20, width-2))
	help := ""
	switch {
	case m.confirmAction != confirmNone:
		help = "Confirm action: Enter/Y approve, Esc/N cancel"
	case currentFindingsView(m) && m.findingSearch:
		help = "Search mode: type to search, Enter/Esc apply, Backspace delete"
	case currentFindingsView(m):
		help = "Findings: 0 all, 1 vuln, 2 warn, 3 info, / search"
	case !m.inDetail && m.globalTab == tabHistory:
		help = "History: x clear saved history"
	case !m.inDetail && m.globalTab == tabNewScan:
		help = "New Scan: Up/Down move focus, Left/Right switch action, Enter execute"
	case !m.inDetail && m.globalTab == tabDashboard:
		help = "Dashboard: Up/Down select scan, Enter open details"
	case m.inDetail && m.detailTab == detailControl:
		help = "Control: p pause/resume, r restart, s stop, Esc back"
	default:
		help = "Tab switch views, Esc back, Ctrl+C interrupt"
	}
	return colorDim + line + "\n" + help + colorReset
}

func renderControlButton(key, label, color string) string {
	return color + colorBold + "[ " + key + " " + label + " ]" + colorReset
}
