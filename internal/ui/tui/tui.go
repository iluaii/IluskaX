package tui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"IluskaX/internal/events"

	tea "github.com/charmbracelet/bubbletea"
)

const (
	colorReset = "\033[0m"
	colorGreen = "\033[38;5;46m"
	colorCyan  = "\033[38;5;51m"
	colorBold  = "\033[1m"
	colorDim   = "\033[2m"
)

type App struct {
	emitter *events.Emitter
	program *tea.Program
	events  <-chan events.Event
	stopCh  chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
}

func New(emitter *events.Emitter) *App {
	if emitter == nil {
		return &App{}
	}
	return &App{
		emitter: emitter,
		events:  emitter.Subscribe(512),
		stopCh:  make(chan struct{}),
	}
}

func (a *App) Start() {
	if a == nil || a.emitter == nil || a.program != nil {
		return
	}
	model := newModel()
	a.program = tea.NewProgram(model, tea.WithAltScreen())
	a.wg.Add(2)
	go func() {
		defer a.wg.Done()
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
	a.program = nil
}

type eventMsg events.Event
type tickMsg time.Time
type quitMsg struct{}

type model struct {
	width        int
	height       int
	target       string
	currentPhase string
	scanned      int64
	total        int64
	startedAt    time.Time
	reportPath   string
	finished     bool
	logs         []string
	findings     []string
	infoCount    int
	warningCount int
	vulnCount    int
}

func newModel() model {
	return model{
		startedAt: time.Now(),
		logs:      make([]string, 0, 256),
		findings:  make([]string, 0, 64),
	}
}

func (m model) Init() tea.Cmd {
	return tickCmd()
}

func tickCmd() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = v.Width
		m.height = v.Height
	case tickMsg:
		if m.finished {
			return m, nil
		}
		return m, tickCmd()
	case quitMsg:
		return m, tea.Quit
	case eventMsg:
		evt := events.Event(v)
		switch evt.Type {
		case events.EventScanStarted:
			m.target = evt.Payload["target"]
			m.startedAt = evt.Timestamp
		case events.EventPhaseStarted:
			m.currentPhase = evt.Phase
			m.scanned = 0
			m.total = evt.Total
			m.pushLog(fmt.Sprintf("[PHASE] %s", evt.Phase))
		case events.EventPhaseProgress:
			m.currentPhase = evt.Phase
			m.scanned = evt.Scanned
			m.total = evt.Total
		case events.EventLogMessage:
			for _, line := range splitLines(evt.Message) {
				m.pushLog(line)
			}
		case events.EventFindingAdded:
			level := evt.Payload["level"]
			kind := evt.Payload["type"]
			url := evt.Payload["url"]
			switch level {
			case "vulnerability":
				m.vulnCount++
			case "warning":
				m.warningCount++
			default:
				m.infoCount++
			}
			m.findings = append(m.findings, fmt.Sprintf("[%s] %s %s", strings.ToUpper(level), kind, url))
			if len(m.findings) > 8 {
				m.findings = m.findings[len(m.findings)-8:]
			}
		case events.EventReportWritten:
			m.reportPath = evt.Payload["path"]
		case events.EventScanFinished:
			m.finished = true
		}
	}
	return m, nil
}

func (m model) View() string {
	width := m.width
	if width <= 0 {
		width = 100
	}
	logHeight := m.height - 11
	if logHeight < 8 {
		logHeight = 8
	}
	logs := m.logs
	if len(logs) > logHeight {
		logs = logs[len(logs)-logHeight:]
	}

	divider := strings.Repeat("─", maxInt(20, width-2))
	var sb strings.Builder
	sb.WriteString(colorCyan + colorBold + " IluskaX TUI " + colorReset)
	sb.WriteString(colorDim + "press Ctrl+C to stop" + colorReset + "\n")
	sb.WriteString(colorDim + divider + colorReset + "\n")

	target := m.target
	if target == "" {
		target = "preparing..."
	}
	sb.WriteString(fmt.Sprintf("%sTarget:%s %s\n", colorBold, colorReset, target))
	sb.WriteString(fmt.Sprintf("%sPhase:%s %s   %sProgress:%s %d/%d   %sElapsed:%s %s\n",
		colorBold, colorReset, valueOrDash(m.currentPhase),
		colorBold, colorReset, m.scanned, m.total,
		colorBold, colorReset, time.Since(m.startedAt).Round(time.Second),
	))
	sb.WriteString(fmt.Sprintf("%sFindings:%s vuln=%d warn=%d info=%d\n",
		colorBold, colorReset, m.vulnCount, m.warningCount, m.infoCount))
	if m.reportPath != "" {
		sb.WriteString(fmt.Sprintf("%sReport:%s %s\n", colorBold, colorReset, m.reportPath))
	}
	sb.WriteString(colorDim + divider + colorReset + "\n")
	sb.WriteString(colorBold + " Live Log" + colorReset + "\n")
	for _, line := range logs {
		sb.WriteString(line + "\n")
	}
	if len(m.findings) > 0 {
		sb.WriteString(colorDim + divider + colorReset + "\n")
		sb.WriteString(colorBold + " Recent Findings" + colorReset + "\n")
		for _, f := range m.findings {
			sb.WriteString(f + "\n")
		}
	}
	if m.finished {
		sb.WriteString(colorDim + divider + colorReset + "\n")
		sb.WriteString(colorGreen + colorBold + " Scan complete. Returning to normal output..." + colorReset + "\n")
	}
	return sb.String()
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
	if len(m.logs) > 300 {
		m.logs = m.logs[len(m.logs)-300:]
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

func valueOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
