package tui

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"IluskaX/internal/events"

	tea "github.com/charmbracelet/bubbletea"
)

const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorGreen  = "\033[38;5;46m"
	colorCyan   = "\033[38;5;51m"
	colorBlue   = "\033[38;5;39m"
	colorYellow = "\033[38;5;226m"
	colorRed    = "\033[38;5;196m"
	cursorHide  = "\033[?25l"
	cursorShow  = "\033[?25h"
)

type App struct {
	emitter *events.Emitter
	program *tea.Program
	events  <-chan events.Event
	stopCh  chan struct{}
	doneCh  chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
}

type eventMsg events.Event
type tickMsg time.Time
type quitMsg struct{}

type globalTab int
type detailTab int
type actionMode int
type inputFocus int

const (
	tabDashboard globalTab = iota
	tabFindings
	tabTargets
	tabHistory
	tabNewScan
)

const (
	detailLogs detailTab = iota
	detailFindings
	detailTargets
	detailControl
)

const (
	actionRunNow actionMode = iota
	actionQueue
)

const (
	focusHost inputFocus = iota
	focusFlags
	focusAction
)

type findingItem struct {
	level   string
	kind    string
	url     string
	payload string
	detail  string
}

type launchItem struct {
	target    string
	flags     string
	command   string
	status    string
	createdAt time.Time
	logPath   string
}

type scanEntry struct {
	id         string
	target     string
	status     string
	phase      string
	scanned    int64
	total      int64
	percent    int
	startedAt  time.Time
	endedAt    time.Time
	reportPath string
	donePath   string
	lastEvent  string
	vulnCount  int
	warnCount  int
	infoCount  int
}

type model struct {
	width         int
	height        int
	target        string
	currentPhase  string
	scanned       int64
	total         int64
	startedAt     time.Time
	reportPath    string
	finished      bool
	globalTab     globalTab
	detailTab     detailTab
	inDetail      bool
	selectedScan  int
	detailScan    int
	scroll        int
	statusMessage string
	logs          []string
	findings      []findingItem
	targets       []string
	targetSeen    map[string]bool
	scans         []scanEntry
	history       []launchItem
	queue         []launchItem
	launchHost    string
	launchFlags   string
	action        actionMode
	focus         inputFocus
}

func New(emitter *events.Emitter) *App {
	if emitter == nil {
		return &App{}
	}
	return &App{
		emitter: emitter,
		events:  emitter.Subscribe(512),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

func (a *App) Start() {
	if a == nil || a.emitter == nil || a.program != nil {
		return
	}
	fmt.Fprint(os.Stdout, cursorHide)
	a.program = tea.NewProgram(newModel(), tea.WithAltScreen())
	a.wg.Add(2)
	go func() {
		defer a.wg.Done()
		defer close(a.doneCh)
		_, _ = a.program.Run()
	}()
	go func() {
		defer a.wg.Done()
		for evt := range a.events {
			select {
			case <-a.stopCh:
				return
			default:
			}
			if a.program == nil {
				return
			}
			a.program.Send(eventMsg(evt))
			if evt.Type == events.EventScanFinished {
				return
			}
		}
	}()
}

func (a *App) Stop() {
	if a == nil || a.program == nil {
		return
	}
	a.once.Do(func() {
		close(a.stopCh)
	})
	a.program.Send(quitMsg{})
	a.wg.Wait()
	fmt.Fprint(os.Stdout, cursorShow)
	a.program = nil
}

func (a *App) Wait() {
	if a == nil || a.doneCh == nil {
		return
	}
	<-a.doneCh
}

func newModel() model {
	now := time.Now()
	return model{
		startedAt:  now,
		logs:       make([]string, 0, 512),
		findings:   make([]findingItem, 0, 64),
		targets:    make([]string, 0, 128),
		targetSeen: map[string]bool{},
		scans: []scanEntry{{
			id:        "current",
			target:    "preparing...",
			status:    "running",
			startedAt: now,
		}},
		history: make([]launchItem, 0, 16),
		queue:   make([]launchItem, 0, 16),
		action:  actionRunNow,
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), tea.HideCursor)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = v.Width
		m.height = v.Height
	case tickMsg:
		m.refreshExternalScans()
		return m, tickCmd()
	case quitMsg:
		return m, tea.Sequence(tea.ShowCursor, tea.Quit)
	case tea.KeyMsg:
		return m.updateKey(v)
	case eventMsg:
		m.applyEvent(events.Event(v))
	}
	return m, nil
}

func interruptCmd() tea.Cmd {
	return func() tea.Msg {
		_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
		return nil
	}
}

func (m model) updateKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if !m.inDetail && m.globalTab == tabNewScan && (m.focus == focusHost || m.focus == focusFlags) {
		switch msg.String() {
		case "ctrl+c":
			return m, interruptCmd()
		case "esc":
			if m.finished {
				return m, tea.Quit
			}
			return m, nil
		case "tab":
			m.globalTab = (m.globalTab + 1) % 5
			m.scroll = 0
			return m, nil
		case "shift+tab":
			m.globalTab = (m.globalTab + 4) % 5
			m.scroll = 0
			return m, nil
		case "up":
			if m.focus > focusHost {
				m.focus--
			}
			return m, nil
		case "down":
			if m.focus < focusAction {
				m.focus++
			}
			return m, nil
		case "enter":
			if m.focus == focusHost {
				m.focus = focusFlags
			} else {
				m.focus = focusAction
			}
			return m, nil
		case "backspace", "ctrl+h":
			m.deleteInputChar()
			return m, nil
		case "space":
			m.appendInput(" ")
			return m, nil
		}
		if len(msg.Runes) > 0 {
			m.appendInput(string(msg.Runes))
			return m, nil
		}
	}

	switch msg.String() {
	case "ctrl+c":
		return m, interruptCmd()
	case "esc":
		if m.finished && !m.inDetail {
			return m, tea.Quit
		}
		if m.inDetail {
			m.inDetail = false
			m.scroll = 0
			m.statusMessage = "Returned to dashboard"
		}
		return m, nil
	case "tab":
		if m.inDetail {
			m.detailTab = (m.detailTab + 1) % 4
		} else {
			m.globalTab = (m.globalTab + 1) % 5
		}
		m.scroll = 0
		return m, nil
	case "shift+tab":
		if m.inDetail {
			m.detailTab = (m.detailTab + 3) % 4
		} else {
			m.globalTab = (m.globalTab + 4) % 5
		}
		m.scroll = 0
		return m, nil
	case "left", "h":
		if m.inDetail {
			m.detailTab = (m.detailTab + 3) % 4
		} else if m.globalTab == tabNewScan && m.focus == focusAction {
			m.action = actionRunNow
		} else {
			m.globalTab = (m.globalTab + 4) % 5
		}
		return m, nil
	case "right", "l":
		if m.inDetail {
			m.detailTab = (m.detailTab + 1) % 4
		} else if m.globalTab == tabNewScan && m.focus == focusAction {
			m.action = actionQueue
		} else {
			m.globalTab = (m.globalTab + 1) % 5
		}
		return m, nil
	case "up", "k":
		if m.inDetail {
			if m.scroll > 0 {
				m.scroll--
			}
			return m, nil
		}
		if m.globalTab == tabDashboard && m.selectedScan > 0 {
			m.selectedScan--
		}
		if m.globalTab == tabNewScan && m.focus > focusHost {
			m.focus--
		}
		return m, nil
	case "down", "j":
		if m.inDetail {
			m.scroll++
			return m, nil
		}
		if m.globalTab == tabDashboard && m.selectedScan < len(m.scans)-1 {
			m.selectedScan++
		}
		if m.globalTab == tabNewScan && m.focus < focusAction {
			m.focus++
		}
		return m, nil
	case "enter":
		if m.globalTab == tabDashboard && !m.inDetail && len(m.scans) > 0 {
			m.inDetail = true
			m.detailScan = m.selectedScan
			m.detailTab = detailLogs
			m.scroll = 0
			m.statusMessage = "Opened scan details"
			return m, nil
		}
		if !m.inDetail && m.globalTab == tabNewScan {
			switch m.focus {
			case focusHost:
				m.focus = focusFlags
			case focusFlags:
				m.focus = focusAction
			case focusAction:
				m.executeNewScanAction()
			}
		}
		return m, nil
	case "r":
		if !m.inDetail && m.globalTab == tabNewScan {
			m.action = actionRunNow
			m.executeNewScanAction()
		}
		return m, nil
	case "q":
		if !m.inDetail && m.globalTab == tabNewScan {
			m.action = actionQueue
			m.executeNewScanAction()
			return m, nil
		}
		return m, tea.Quit
	}

	if !m.inDetail && m.globalTab == tabNewScan {
		switch msg.String() {
		case "ctrl+h", "backspace":
			m.deleteInputChar()
			return m, nil
		case "space":
			m.appendInput(" ")
			return m, nil
		}
		if len(msg.Runes) > 0 {
			m.appendInput(string(msg.Runes))
		}
	}

	return m, nil
}

func (m *model) appendInput(s string) {
	switch m.focus {
	case focusHost:
		m.launchHost += s
	case focusFlags:
		m.launchFlags += s
	}
}

func (m *model) deleteInputChar() {
	switch m.focus {
	case focusHost:
		m.launchHost = trimLastRune(m.launchHost)
	case focusFlags:
		m.launchFlags = trimLastRune(m.launchFlags)
	}
}

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
		m.scans = append(m.scans, scanEntry{
			id:        fmt.Sprintf("queued-%d", item.createdAt.UnixNano()),
			target:    target,
			status:    "queued",
			phase:     "waiting",
			startedAt: item.createdAt,
			lastEvent: "Queued from TUI",
		})
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
	m.scans = append(m.scans, scanEntry{
		id:         fmt.Sprintf("launched-%d", item.createdAt.UnixNano()),
		target:     target,
		status:     "running",
		phase:      "external",
		startedAt:  item.createdAt,
		lastEvent:  "Started from dashboard",
		reportPath: logPath,
		donePath:   donePath,
	})
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
			break
		}
		m.targetSeen[u] = true
		m.targets = append(m.targets, u)
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
	if detail && m.detailScan != 0 {
		sb.WriteString("Detailed targets are only tracked for the active in-process scan right now.\n")
		return sb.String()
	}
	if len(m.targets) == 0 {
		sb.WriteString("No targets discovered yet.\n")
		return sb.String()
	}
	grouped := groupTargetsByHost(m.targets)
	lines := renderTargetGroups(grouped)
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
	sb.WriteString(colorDim + fmt.Sprintf("\n%d targets total across %d host(s)", len(m.targets), len(grouped)) + colorReset + "\n")
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
		} else {
			scan.status = "failed"
			scan.endedAt = time.Now()
			scan.lastEvent = shorten(result, 80)
		}
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
