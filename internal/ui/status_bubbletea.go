package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type statusPhaseMsg struct {
	phase string
	total int64
}

type statusSnapshotMsg struct {
	phase    string
	scanned  int64
	total    int64
	rps      float64
	elapsed  string
	progress float64
	eta      string
}

type statusLogMsg struct {
	text string
}

type statusQuitMsg struct{}

type statusTeaModel struct {
	logs     []string
	maxLogs  int
	width    int
	height   int
	phase    string
	scanned  int64
	total    int64
	rps      float64
	elapsed  string
	progress float64
	eta      string
}

func newStatusTeaModel() statusTeaModel {
	return statusTeaModel{
		maxLogs: 24,
		width:   80,
	}
}

func (m statusTeaModel) Init() tea.Cmd { return nil }

func (m statusTeaModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = v.Width
		m.height = v.Height
		if v.Height > 8 {
			m.maxLogs = v.Height - 5
		}
	case statusPhaseMsg:
		m.phase = v.phase
		m.total = v.total
		m.scanned = 0
		m.rps = 0
		m.progress = 0
		m.eta = ""
	case statusSnapshotMsg:
		m.phase = v.phase
		m.scanned = v.scanned
		m.total = v.total
		m.rps = v.rps
		m.elapsed = v.elapsed
		m.progress = v.progress
		m.eta = v.eta
	case statusLogMsg:
		for _, line := range splitLogLines(v.text) {
			m.logs = append(m.logs, line)
			if len(m.logs) > m.maxLogs {
				m.logs = m.logs[len(m.logs)-m.maxLogs:]
			}
		}
	case statusQuitMsg:
		return m, tea.Quit
	}
	return m, nil
}

func (m statusTeaModel) View() string {
	var sb strings.Builder
	for _, l := range m.logs {
		sb.WriteString(l)
		sb.WriteString("\n")
	}

	barWidth := 20
	filled := int(float64(barWidth) * m.progress)
	if filled < 0 {
		filled = 0
	}
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	phase := Truncate(m.phase, 16)
	dividerWidth := 56
	if m.width > 0 {
		if w := m.width - 2; w > 20 && w < 120 {
			dividerWidth = w
		}
	}
	divider := colorDim + strings.Repeat("─", dividerWidth) + colorReset

	line1 := " " + colorCyan + colorBold + phase + colorReset +
		"  " + colorGreen + "[" + itoa(m.scanned) + "/" + itoa(m.total) + "]" + colorReset +
		"  " + colorYellow + ftoa1(m.rps) + " rps" + colorReset +
		"  " + colorDim + m.elapsed + colorReset

	progressLine := " " + colorCyan + bar + colorReset +
		"  " + colorBold + itoa(int64(m.progress*100)) + "%" + colorReset
	if m.eta != "" {
		progressLine += " " + colorBlue + "ETA " + m.eta + colorReset
	}

	sb.WriteString(divider + "\n")
	sb.WriteString(line1 + "\n")
	sb.WriteString(progressLine)
	return sb.String()
}

func splitLogLines(s string) []string {
	if s == "" {
		return nil
	}
	normalized := strings.ReplaceAll(s, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	parts := strings.Split(normalized, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func itoa(v int64) string {
	return fmt.Sprintf("%d", v)
}

func ftoa1(v float64) string {
	return fmt.Sprintf("%.1f", v)
}
