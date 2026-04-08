package tui

import (
	"fmt"
	"strings"
)

func (m model) View() string {
	width := m.width
	if width <= 0 {
		width = 120
	}
	var sb strings.Builder
	sb.WriteString(cursorHide)
	sb.WriteString(m.renderHeader(width))
	sb.WriteString("\n")
	if m.inDetail {
		sb.WriteString(m.renderDetailView(width))
	} else {
		sb.WriteString(m.renderGlobalView(width))
	}
	if m.statusMessage != "" {
		sb.WriteString("\n" + colorDim + m.statusMessage + colorReset)
	}
	return sb.String()
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
	sb.WriteString(colorBold + colorCyan + " " + title + " " + colorReset)
	sb.WriteString(colorDim + "Tab switch  Enter open/run  Esc back  q quit" + colorReset + "\n")
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
			selected.target, strings.ToUpper(selected.status), valueOrDash(selected.phase), selected.percent, elapsedForScan(selected)))
		sb.WriteString(fmt.Sprintf("Selected findings: vuln=%d warn=%d info=%d\n",
			selected.vulnCount, selected.warnCount, selected.infoCount))
	}
	sb.WriteString("\n")
	sb.WriteString(colorBold + " Actions" + colorReset + "\n")
	sb.WriteString("Enter: open selected scan   Tab: switch main tabs   New Scan tab: create another run or queue item\n")
	if m.finished {
		sb.WriteString(colorGreen + "\nCurrent scan finished. Press Esc to leave TUI." + colorReset + "\n")
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
	lines := m.logs
	if scan, ok := m.selectedDetailScan(); ok && m.detailScan != 0 {
		lines = readLogPreview(scan.reportPath, 400)
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
		if m.scroll > maxScroll {
			m.scroll = maxScroll
		}
		start = maxScroll - m.scroll
		lines = lines[start : start+logHeight]
	}
	for _, line := range lines {
		sb.WriteString(line + "\n")
	}
	sb.WriteString("\n")
	sb.WriteString(colorDim + fmt.Sprintf("Showing %d/%d log lines", len(lines), len(m.logs)) + colorReset + "\n")
	if m.finished {
		sb.WriteString(colorGreen + "Scan finished. Press Esc to close TUI." + colorReset + "\n")
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
	if len(m.findings) == 0 {
		sb.WriteString("No findings yet.\n")
		return sb.String()
	}
	for _, item := range m.findings {
		levelColor := colorCyan
		switch item.level {
		case "vulnerability":
			levelColor = colorRed
		case "warning":
			levelColor = colorYellow
		}
		sb.WriteString(fmt.Sprintf("%s[%s]%s %s %s\n", levelColor, strings.ToUpper(item.level), colorReset, item.kind, item.url))
		if item.payload != "" {
			sb.WriteString("  " + shorten(item.payload, maxInt(30, width-8)) + "\n")
		}
		if item.detail != "" {
			sb.WriteString("  " + colorDim + item.detail + colorReset + "\n")
		}
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
		return sb.String()
	}
	for _, item := range m.history {
		sb.WriteString(fmt.Sprintf("%s%s%s  %s\n", colorGreen, strings.ToUpper(item.status), colorReset, item.target))
		sb.WriteString("  " + item.command + "\n")
		if item.logPath != "" {
			sb.WriteString("  " + colorDim + item.logPath + colorReset + "\n")
		}
	}
	if len(m.queue) > 0 {
		sb.WriteString("\n" + colorBold + " Queue" + colorReset + "\n")
		for _, item := range m.queue {
			sb.WriteString(fmt.Sprintf("%sQUEUED%s  %s\n", colorYellow, colorReset, item.target))
			sb.WriteString("  " + item.command + "\n")
		}
	}
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
	sb.WriteString("Enter: next field / execute action   R: run now   Q: queue   Left/Right: switch action\n")
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
	sb.WriteString(fmt.Sprintf("Status: %s\n", current.status))
	sb.WriteString(fmt.Sprintf("Phase: %s\n", valueOrDash(current.phase)))
	sb.WriteString(fmt.Sprintf("Progress: %d%% (%d/%d)\n", current.percent, current.scanned, current.total))
	sb.WriteString(fmt.Sprintf("Elapsed: %s\n", elapsedForScan(current)))
	if current.reportPath != "" {
		sb.WriteString(fmt.Sprintf("Output: %s\n", current.reportPath))
	}
	sb.WriteString("\n")
	sb.WriteString("This detail view is for the selected scan.\n")
	sb.WriteString("Use Esc to return to the global dashboard and launch or queue more scans.\n")
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
		return colorBold + "Action:" + colorReset + " " + left + "  " + right + "\n"
	}
	return "Action: " + left + "  " + right + "\n"
}

func renderScanLine(scan scanEntry) string {
	return fmt.Sprintf("%-18s  %-10s  %-18s  %3d%%  vuln=%d warn=%d info=%d",
		shorten(scan.target, 18),
		strings.ToUpper(scan.status),
		shorten(valueOrDash(scan.phase), 18),
		scan.percent,
		scan.vulnCount,
		scan.warnCount,
		scan.infoCount,
	)
}
