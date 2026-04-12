package tui

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"IluskaX/internal/events"
)

func (m *model) executeNewScanAction() {
	target := strings.TrimSpace(m.launchHost)
	flags := strings.TrimSpace(m.launchFlags)
	if target == "" {
		m.setTransientStatus("Target is required for a new scan")
		return
	}

	command := "./luska -u " + target
	if flags != "" {
		command += " " + flags
	}

	item := launchItem{
		target:    target,
		flags:     flags,
		command:   command,
		createdAt: time.Now(),
	}

	if m.action == actionQueue {
		item.status = "queued"
		m.queue = append(m.queue, item)
		scan := scanEntry{
			id:        fmt.Sprintf("queued-%d", item.createdAt.UnixNano()),
			target:    target,
			status:    "queued",
			phase:     "waiting",
			startedAt: item.createdAt,
			lastEvent: "Queued from TUI",
		}
		addScanTarget(&scan, target)
		m.addTarget(target)
		m.scans = append(m.scans, scan)
		m.setTransientStatus("Scan queued in dashboard")
		return
	}

	logPath, donePath, pid, err := launchBackgroundScan(target, flags)
	if err != nil {
		m.setTransientStatus("Launch failed: " + err.Error())
		return
	}
	item.status = "running"
	item.logPath = logPath
	m.history = append([]launchItem{item}, m.history...)
	m.persistHistory()
	scan := scanEntry{
		id:         fmt.Sprintf("launched-%d", item.createdAt.UnixNano()),
		target:     target,
		flags:      flags,
		status:     "running",
		phase:      "starting",
		startedAt:  item.createdAt,
		lastEvent:  "Started from dashboard",
		reportPath: logPath,
		donePath:   donePath,
		pid:        pid,
	}
	addScanTarget(&scan, target)
	m.addTarget(target)
	m.scans = append(m.scans, scan)
	m.setTransientStatus("Scan launched in background")
	m.launchHost = ""
	m.launchFlags = ""
}

func launchBackgroundScan(target, flags string) (string, string, int, error) {
	if err := os.MkdirAll("Poutput", 0755); err != nil {
		return "", "", 0, err
	}
	tag := sanitizeName(target)
	if tag == "" {
		tag = "scan"
	}
	logPath := filepath.Join("Poutput", fmt.Sprintf("dashboard_%s_%s.log", tag, time.Now().Format("2006-01-02_15-04-05")))
	donePath := logPath + ".done"
	logFile, err := os.Create(logPath)
	if err != nil {
		return "", "", 0, err
	}

	args := []string{"-u", target}
	if flags != "" {
		args = append(args, strings.Fields(flags)...)
	}

	cmd := exec.Command("./luska", args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return "", "", 0, err
	}
	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	go func() {
		waitErr := cmd.Wait()
		exitStatus := "ok"
		if waitErr != nil {
			exitStatus = waitErr.Error()
		}
		_ = os.WriteFile(donePath, []byte(exitStatus), 0644)
		_ = logFile.Close()
	}()

	return logPath, donePath, pid, nil
}

func parsePhaseFromLog(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := splitLines(string(data))
	phase := ""
	for _, line := range lines {
		clean := stripANSI(strings.TrimSpace(line))
		if !strings.Contains(clean, "[PHASE") {
			continue
		}
		if strings.Contains(clean, "SKIPPED") {
			continue
		}
		for _, marker := range []string{
			"[PHASE 0.1]", "[PHASE 0]", "[PHASE 1]", "[PHASE 2]",
			"[PHASE 3-POST]", "[PHASE 3.1]", "[PHASE 3]",
			"[PHASE 4]", "[PHASE 5]",
		} {
			if strings.Contains(clean, marker) {
				label := strings.TrimPrefix(marker, "[PHASE ")
				label = strings.TrimSuffix(label, "]")
				rest := strings.TrimSpace(strings.SplitN(clean, marker, 2)[1])
				if idx := strings.Index(rest, " - "); idx != -1 {
					rest = strings.TrimSpace(rest[:idx])
				}
				if idx := strings.Index(rest, "\n"); idx != -1 {
					rest = rest[:idx]
				}
				rest = strings.TrimPrefix(rest, "- ")
				name := shorten(rest, 20)
				if name == "" {
					name = "Phase " + label
				}
				phase = name
				break
			}
		}
	}
	return phase
}

func parseProgressFromLog(path string) (scanned, total int64, percent int) {
	if strings.TrimSpace(path) == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := splitLines(string(data))
	for i := len(lines) - 1; i >= 0; i-- {
		clean := stripANSI(strings.TrimSpace(lines[i]))
		if !strings.Contains(clean, "[") || !strings.Contains(clean, "/") {
			continue
		}
		start := strings.Index(clean, "[")
		end := strings.Index(clean, "]")
		if start < 0 || end <= start {
			continue
		}
		inner := clean[start+1 : end]
		parts := strings.SplitN(inner, "/", 2)
		if len(parts) != 2 {
			continue
		}
		s := parseInt(strings.TrimSpace(parts[0]))
		t := parseInt(strings.TrimSpace(parts[1]))
		if s >= 0 && t > 0 {
			scanned = int64(s)
			total = int64(t)
			percent = int((scanned * 100) / total)
			return
		}
	}
	return
}

func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func (m *model) applyEvent(evt events.Event) {
	switch evt.Type {
	case events.EventScanStarted:
		m.target = evt.Payload["target"]
		if m.target == "" {
			m.target = evt.Message
		}
		m.startedAt = evt.Timestamp
		m.updateCurrentScan(func(s *scanEntry) {
			s.target = valueOrFallback(m.target, "current scan")
			s.status = "running"
			s.startedAt = evt.Timestamp
			s.endedAt = time.Time{}
			s.lastEvent = "Scan started"
			addScanTarget(s, m.target)
		})
	case events.EventPhaseStarted:
		m.currentPhase = evt.Phase
		m.scanned = 0
		m.total = evt.Total
		m.pushLog(fmt.Sprintf("[PHASE] %s", evt.Phase))
		m.updateCurrentScan(func(s *scanEntry) {
			s.phase = evt.Phase
			s.scanned = 0
			s.total = evt.Total
			s.percent = 0
			s.status = "running"
			s.lastEvent = "Phase started"
		})
	case events.EventPhaseProgress:
		m.currentPhase = evt.Phase
		m.scanned = evt.Scanned
		m.total = evt.Total
		m.updateCurrentScan(func(s *scanEntry) {
			s.phase = evt.Phase
			s.scanned = evt.Scanned
			s.total = evt.Total
			s.percent = percent(evt.Scanned, evt.Total)
		})
	case events.EventLogMessage:
		for _, line := range splitLines(evt.Message) {
			m.pushLog(line)
		}
		m.updateCurrentScan(func(s *scanEntry) {
			s.lastEvent = shorten(stripANSI(strings.TrimSpace(evt.Message)), 80)
		})
	case events.EventFindingAdded:
		item := findingItem{
			level:   evt.Payload["level"],
			kind:    evt.Payload["type"],
			url:     evt.Payload["url"],
			payload: evt.Payload["payload"],
			detail:  evt.Payload["detail"],
		}
		m.findings = append(m.findings, item)
		m.updateCurrentScan(func(s *scanEntry) {
			switch item.level {
			case "vulnerability":
				s.vulnCount++
			case "warning":
				s.warnCount++
			default:
				s.infoCount++
			}
			s.lastEvent = fmt.Sprintf("%s %s", strings.ToUpper(item.level), item.kind)
		})
	case events.EventSitemapAdded:
		u := evt.Payload["url"]
		if u == "" || m.targetSeen[u] {
			m.updateCurrentScan(func(s *scanEntry) {
				addScanTarget(s, u)
			})
			break
		}
		m.targetSeen[u] = true
		m.targets = append(m.targets, u)
		m.updateCurrentScan(func(s *scanEntry) {
			addScanTarget(s, u)
		})
	case events.EventReportWritten:
		m.reportPath = evt.Payload["path"]
		m.updateCurrentScan(func(s *scanEntry) {
			s.reportPath = m.reportPath
			s.lastEvent = "Report written"
		})
	case events.EventScanFinished:
		m.finished = true
		m.updateCurrentScan(func(s *scanEntry) {
			s.status = "finished"
			s.percent = 100
			s.endedAt = evt.Timestamp
			s.pid = 0
			s.lastEvent = "Scan finished"
		})
		m.refreshCompletionStatus()
		if m.target != "" {
			m.history = append([]launchItem{{
				target:    m.target,
				command:   "./pentest current-session",
				status:    "finished",
				createdAt: evt.Timestamp,
				logPath:   m.reportPath,
			}}, m.history...)
			m.persistHistory()
		}
	}
}

func (m *model) performConfirmedAction() {
	switch m.confirmAction {
	case confirmNewScan:
		m.executeNewScanAction()
	case confirmClearHistory:
		m.clearHistory()
		m.setTransientStatus("History cleared")
	case confirmPauseResume:
		m.togglePauseSelectedScan()
	case confirmRestart:
		m.restartSelectedScan()
	case confirmStop:
		m.stopSelectedScan()
	}
	m.clearConfirm()
}

func (m *model) requestNewScanConfirm() {
	actionLabel := "run"
	if m.action == actionQueue {
		actionLabel = "queue"
	}
	target := strings.TrimSpace(m.launchHost)
	if target == "" {
		target = "<target>"
	}
	m.requestConfirm(confirmNewScan, fmt.Sprintf("Confirm %s for %s?", actionLabel, target))
}

func (m *model) requestClearHistoryConfirm() {
	m.requestConfirm(confirmClearHistory, "Clear saved history and queued items?")
}

func (m *model) requestPauseResumeConfirm() {
	scan, _, ok := m.selectedControllableScan()
	if !ok {
		m.setTransientStatus("Pause is only available for background scans launched from TUI")
		return
	}
	label := "pause"
	if scan.status == "paused" {
		label = "resume"
	}
	m.requestConfirm(confirmPauseResume, fmt.Sprintf("Confirm %s for %s?", label, scan.target))
}

func (m *model) requestRestartConfirm() {
	scan, _, ok := m.selectedControllableScan()
	if !ok {
		m.setTransientStatus("Restart is only available for background scans launched from TUI")
		return
	}
	m.requestConfirm(confirmRestart, fmt.Sprintf("Restart %s?", scan.target))
}

func (m *model) requestStopConfirm() {
	scan, _, ok := m.selectedControllableScan()
	if !ok {
		m.setTransientStatus("Stop is only available for background scans launched from TUI")
		return
	}
	m.requestConfirm(confirmStop, fmt.Sprintf("Stop %s?", scan.target))
}

func (m *model) togglePauseSelectedScan() {
	scan, idx, ok := m.selectedControllableScan()
	if !ok {
		m.setTransientStatus("Pause is only available for background scans launched from TUI")
		return
	}
	if scan.pid <= 0 {
		m.setTransientStatus("No running process found for selected scan")
		return
	}
	sig := syscall.SIGSTOP
	nextStatus := "paused"
	nextEvent := "Paused from control tab"
	message := "Scan paused"
	if scan.status == "paused" {
		sig = syscall.SIGCONT
		nextStatus = "running"
		nextEvent = "Resumed from control tab"
		message = "Scan resumed"
	}
	if err := syscall.Kill(scan.pid, sig); err != nil {
		m.setTransientStatus("Pause/resume failed: " + err.Error())
		return
	}
	m.scans[idx].status = nextStatus
	m.scans[idx].lastEvent = nextEvent
	m.setTransientStatus(message)
}

func (m *model) restartSelectedScan() {
	scan, idx, ok := m.selectedControllableScan()
	if !ok {
		m.setTransientStatus("Restart is only available for background scans launched from TUI")
		return
	}
	if scan.status == "running" || scan.status == "paused" {
		if scan.pid > 0 {
			if scan.status == "paused" {
				_ = syscall.Kill(scan.pid, syscall.SIGCONT)
			}
			_ = syscall.Kill(scan.pid, syscall.SIGINT)
		}
	}
	logPath, donePath, pid, err := launchBackgroundScan(scan.target, scan.flags)
	if err != nil {
		m.setTransientStatus("Restart failed: " + err.Error())
		return
	}
	m.scans[idx].status = "running"
	m.scans[idx].phase = "starting"
	m.scans[idx].startedAt = time.Now()
	m.scans[idx].endedAt = time.Time{}
	m.scans[idx].percent = 0
	m.scans[idx].reportPath = logPath
	m.scans[idx].donePath = donePath
	m.scans[idx].crawlPath = ""
	m.scans[idx].pid = pid
	m.scans[idx].lastEvent = "Restarted from control tab"
	item := launchItem{
		target:    scan.target,
		flags:     scan.flags,
		command:   "./luska -u " + scan.target + strings.TrimPrefix(" "+strings.TrimSpace(scan.flags), " "),
		status:    "running",
		createdAt: time.Now(),
		logPath:   logPath,
	}
	m.history = append([]launchItem{item}, m.history...)
	m.persistHistory()
	m.setTransientStatus("Scan restarted")
}

func (m *model) stopSelectedScan() {
	scan, idx, ok := m.selectedControllableScan()
	if !ok {
		m.setTransientStatus("Stop is only available for background scans launched from TUI")
		return
	}
	if scan.pid > 0 {
		if scan.status == "paused" {
			_ = syscall.Kill(scan.pid, syscall.SIGCONT)
		}
		if err := syscall.Kill(scan.pid, syscall.SIGINT); err != nil {
			m.setTransientStatus("Stop failed: " + err.Error())
			return
		}
	}
	m.scans[idx].status = "stopped"
	m.scans[idx].endedAt = time.Now()
	m.scans[idx].pid = 0
	m.scans[idx].lastEvent = "Stopped from control tab"
	m.setTransientStatus("Scan stopped")
}

func (m model) selectedControllableScan() (scanEntry, int, bool) {
	if !m.inDetail || m.detailTab != detailControl {
		return scanEntry{}, -1, false
	}
	if m.detailScan <= 0 || m.detailScan >= len(m.scans) {
		return scanEntry{}, -1, false
	}
	scan := m.scans[m.detailScan]
	if scan.phase != "external" && scan.reportPath == "" {
		return scanEntry{}, -1, false
	}
	return scan, m.detailScan, true
}

func (m *model) updateCurrentScan(fn func(*scanEntry)) {
	if len(m.scans) == 0 {
		m.scans = append(m.scans, scanEntry{id: "current", startedAt: time.Now()})
	}
	fn(&m.scans[0])
}

func (m *model) addTarget(target string) {
	target = strings.TrimSpace(target)
	if target == "" || m.targetSeen[target] {
		return
	}
	m.targetSeen[target] = true
	m.targets = append(m.targets, target)
}

func addScanTarget(scan *scanEntry, target string) {
	if scan == nil {
		return
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return
	}
	if parsed, err := url.Parse(target); err != nil || (parsed.Host == "" && !strings.HasPrefix(target, "/")) {
		return
	}
	for _, existing := range scan.targets {
		if existing == target {
			return
		}
	}
	scan.targets = append(scan.targets, target)
}

func countStatus(scans []scanEntry, status string) int {
	total := 0
	for _, scan := range scans {
		if scan.status == status {
			total++
		}
	}
	return total
}

func (m model) selectedDashboardScan() scanEntry {
	if len(m.scans) == 0 {
		return scanEntry{target: "-", status: "-", phase: "-"}
	}
	if m.selectedScan < 0 {
		return m.scans[0]
	}
	if m.selectedScan >= len(m.scans) {
		return m.scans[len(m.scans)-1]
	}
	return m.scans[m.selectedScan]
}

func (m *model) refreshExternalScans() {
	changed := false
	for i := range m.scans {
		scan := &m.scans[i]
		m.syncExternalScanTargets(scan)

		if scan.reportPath != "" && (scan.status == "running" || scan.status == "paused") {
			if phase := parsePhaseFromLog(scan.reportPath); phase != "" {
				scan.phase = phase
			}
			s, t, pct := parseProgressFromLog(scan.reportPath)
			if t > 0 {
				scan.scanned = s
				scan.total = t
				scan.percent = pct
			}
		}

		if scan.donePath == "" || scan.status == "finished" || scan.status == "failed" || scan.status == "paused" {
			continue
		}
		data, err := os.ReadFile(scan.donePath)
		if err != nil {
			continue
		}
		result := strings.TrimSpace(string(data))
		if result == "" || result == "ok" {
			scan.status = "finished"
			scan.percent = 100
			scan.endedAt = time.Now()
			scan.pid = 0
			scan.lastEvent = "Background scan finished"
			m.syncExternalScanTargets(scan)
			changed = true
		} else {
			scan.status = "failed"
			scan.endedAt = time.Now()
			scan.pid = 0
			scan.lastEvent = shorten(result, 80)
			m.syncExternalScanTargets(scan)
			changed = true
		}
	}
	if changed {
		m.refreshCompletionStatus()
	}
}

func (m *model) syncExternalScanTargets(scan *scanEntry) {
	if scan == nil || scan.reportPath == "" {
		return
	}
	if scan.crawlPath == "" {
		scan.crawlPath = parseCrawlPathFromLog(scan.reportPath)
	}
	if scan.crawlPath == "" {
		return
	}
	for _, target := range readCrawlTargets(scan.crawlPath) {
		addScanTarget(scan, target)
		m.addTarget(target)
	}
}

func (m model) selectedDetailScan() (scanEntry, bool) {
	if m.detailScan < 0 || m.detailScan >= len(m.scans) {
		return scanEntry{}, false
	}
	return m.scans[m.detailScan], true
}

func elapsedForScan(scan scanEntry) time.Duration {
	if scan.startedAt.IsZero() {
		return 0
	}
	if !scan.endedAt.IsZero() {
		return scan.endedAt.Sub(scan.startedAt).Round(time.Second)
	}
	return time.Since(scan.startedAt).Round(time.Second)
}