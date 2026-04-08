package tui

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"IluskaX/internal/events"
)

func (m *model) executeNewScanAction() {
	target := strings.TrimSpace(m.launchHost)
	flags := strings.TrimSpace(m.launchFlags)
	if target == "" {
		m.statusMessage = "Target is required for a new scan"
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
		m.statusMessage = "Scan queued in dashboard"
		return
	}

	logPath, donePath, err := launchBackgroundScan(target, flags)
	if err != nil {
		m.statusMessage = "Launch failed: " + err.Error()
		return
	}
	item.status = "running"
	item.logPath = logPath
	m.history = append([]launchItem{item}, m.history...)
	scan := scanEntry{
		id:         fmt.Sprintf("launched-%d", item.createdAt.UnixNano()),
		target:     target,
		status:     "running",
		phase:      "external",
		startedAt:  item.createdAt,
		lastEvent:  "Started from dashboard",
		reportPath: logPath,
		donePath:   donePath,
	}
	addScanTarget(&scan, target)
	m.addTarget(target)
	m.scans = append(m.scans, scan)
	m.statusMessage = "Scan launched in background"
	m.launchHost = ""
	m.launchFlags = ""
}

func launchBackgroundScan(target, flags string) (string, string, error) {
	if err := os.MkdirAll("Poutput", 0755); err != nil {
		return "", "", err
	}
	tag := sanitizeName(target)
	if tag == "" {
		tag = "scan"
	}
	logPath := filepath.Join("Poutput", fmt.Sprintf("dashboard_%s_%s.log", tag, time.Now().Format("2006-01-02_15-04-05")))
	donePath := logPath + ".done"
	logFile, err := os.Create(logPath)
	if err != nil {
		return "", "", err
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
		return "", "", err
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

	return logPath, donePath, nil
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
		m.statusMessage = fmt.Sprintf("Scan %s finished. Press Esc to close TUI.", valueOrFallback(m.target, "current"))
		m.updateCurrentScan(func(s *scanEntry) {
			s.status = "finished"
			s.percent = 100
			s.endedAt = evt.Timestamp
			s.lastEvent = "Scan finished"
		})
		if m.target != "" {
			m.history = append([]launchItem{{
				target:    m.target,
				command:   "./pentest current-session",
				status:    "finished",
				createdAt: evt.Timestamp,
				logPath:   m.reportPath,
			}}, m.history...)
		}
	}
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
	for i := range m.scans {
		scan := &m.scans[i]
		m.syncExternalScanTargets(scan)
		if scan.donePath == "" || scan.status == "finished" || scan.status == "failed" {
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
			scan.lastEvent = "Background scan finished"
			m.syncExternalScanTargets(scan)
		} else {
			scan.status = "failed"
			scan.endedAt = time.Now()
			scan.lastEvent = shorten(result, 80)
			m.syncExternalScanTargets(scan)
		}
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
