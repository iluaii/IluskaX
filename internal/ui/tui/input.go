package tui

import (
	"os"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
)

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
