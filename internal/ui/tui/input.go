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
	if m.confirmAction != confirmNone {
		switch msg.String() {
		case "ctrl+c":
			return m, interruptCmd()
		case "enter", "y":
			m.performConfirmedAction()
			return m, nil
		case "esc", "n":
			m.clearConfirm()
			m.setTransientStatus("Action canceled")
			return m, nil
		default:
			return m, nil
		}
	}

	if currentFindingsView(m) && m.findingSearch {
		switch msg.String() {
		case "ctrl+c":
			return m, interruptCmd()
		case "esc", "enter":
			m.findingSearch = false
			return m, nil
		case "backspace", "ctrl+h":
			m.findingQuery = trimLastRune(m.findingQuery)
			return m, nil
		case "space":
			m.findingQuery += " "
			return m, nil
		}
		if len(msg.Runes) > 0 {
			m.findingQuery += string(msg.Runes)
			return m, nil
		}
	}

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
		if m.finished && !m.inDetail && !m.hasActiveBackgroundScans() {
			return m, tea.Quit
		}
		if m.finished && !m.inDetail && m.hasActiveBackgroundScans() {
			m.setTransientStatus("Background scans are still running. Use q to quit anyway.")
			return m, nil
		}
		if m.inDetail {
			m.inDetail = false
			m.scroll = 0
			m.followLogs = true
			m.setTransientStatus("Returned to dashboard")
		}
		return m, nil
	case "tab":
		if m.inDetail {
			m.detailTab = (m.detailTab + 1) % 4
			if m.detailTab == detailLogs {
				m.followLogs = true
				m.scroll = 0
			}
		} else {
			m.globalTab = (m.globalTab + 1) % 5
		}
		m.scroll = 0
		return m, nil
	case "shift+tab":
		if m.inDetail {
			m.detailTab = (m.detailTab + 3) % 4
			if m.detailTab == detailLogs {
				m.followLogs = true
				m.scroll = 0
			}
		} else {
			m.globalTab = (m.globalTab + 4) % 5
		}
		m.scroll = 0
		return m, nil
	case "left", "h":
		if m.inDetail {
			m.detailTab = (m.detailTab + 3) % 4
			if m.detailTab == detailLogs {
				m.followLogs = true
				m.scroll = 0
			}
		} else if m.globalTab == tabNewScan && m.focus == focusAction {
			m.action = actionRunNow
		} else {
			m.globalTab = (m.globalTab + 4) % 5
		}
		return m, nil
	case "right", "l":
		if m.inDetail {
			m.detailTab = (m.detailTab + 1) % 4
			if m.detailTab == detailLogs {
				m.followLogs = true
				m.scroll = 0
			}
		} else if m.globalTab == tabNewScan && m.focus == focusAction {
			m.action = actionQueue
		} else {
			m.globalTab = (m.globalTab + 1) % 5
		}
		return m, nil
	case "up", "k":
		if currentFindingsView(m) && !m.findingSearch {
			maxScroll := m.findingsMaxScroll(m.width)
			if m.scroll > 0 {
				m.scroll--
			}
			if m.scroll > maxScroll {
				m.scroll = maxScroll
			}
			return m, nil
		}
		if m.inDetail {
			if m.detailTab == detailLogs {
				maxScroll := m.logMaxScroll()
				if m.followLogs {
					m.followLogs = false
					m.scroll = maxScroll
				}
				if m.scroll > 0 {
					m.scroll--
				}
			} else if m.scroll > 0 {
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
		if currentFindingsView(m) && !m.findingSearch {
			maxScroll := m.findingsMaxScroll(m.width)
			if m.scroll < maxScroll {
				m.scroll++
			}
			return m, nil
		}
		if m.inDetail {
			if m.detailTab == detailLogs {
				maxScroll := m.logMaxScroll()
				if !m.followLogs {
					if m.scroll < maxScroll {
						m.scroll++
					} else {
						m.followLogs = true
						m.scroll = 0
					}
				}
			} else {
				m.scroll++
			}
			return m, nil
		}
		if m.globalTab == tabDashboard && m.selectedScan < len(m.scans)-1 {
			m.selectedScan++
		}
		if m.globalTab == tabNewScan && m.focus < focusAction {
			m.focus++
		}
		return m, nil
	case "pgup", "pageup":
		if currentFindingsView(m) && !m.findingSearch {
			maxScroll := m.findingsMaxScroll(m.width)
			step := maxInt(1, m.height/2)
			m.scroll -= step
			if m.scroll < 0 {
				m.scroll = 0
			}
			if m.scroll > maxScroll {
				m.scroll = maxScroll
			}
			return m, nil
		}
	case "pgdn", "pagedown":
		if currentFindingsView(m) && !m.findingSearch {
			maxScroll := m.findingsMaxScroll(m.width)
			step := maxInt(1, m.height/2)
			m.scroll += step
			if m.scroll > maxScroll {
				m.scroll = maxScroll
			}
			return m, nil
		}
	case "home":
		if currentFindingsView(m) && !m.findingSearch {
			m.scroll = 0
			return m, nil
		}
	case "end":
		if currentFindingsView(m) && !m.findingSearch {
			m.scroll = m.findingsMaxScroll(m.width)
			return m, nil
		}
	case "enter":
		if m.globalTab == tabDashboard && !m.inDetail && len(m.scans) > 0 {
			m.inDetail = true
			m.detailScan = m.selectedScan
			m.detailTab = detailLogs
			m.scroll = 0
			m.followLogs = true
			m.setTransientStatus("Opened scan details")
			return m, nil
		}
		if !m.inDetail && m.globalTab == tabNewScan {
			switch m.focus {
			case focusHost:
				m.focus = focusFlags
			case focusFlags:
				m.focus = focusAction
			case focusAction:
				m.requestNewScanConfirm()
			}
		}
		return m, nil
	case "r":
		if m.inDetail && m.detailTab == detailControl {
			m.requestRestartConfirm()
			return m, nil
		}
		return m, nil
	case "p":
		if m.inDetail && m.detailTab == detailControl {
			m.requestPauseResumeConfirm()
			return m, nil
		}
	case "s":
		if m.inDetail && m.detailTab == detailControl {
			m.requestStopConfirm()
			return m, nil
		}
	case "/":
		if currentFindingsView(m) {
			m.findingSearch = true
			return m, nil
		}
	case "0", "1", "2", "3":
		if currentFindingsView(m) {
			switch msg.String() {
			case "0":
				m.findingFilter = filterAll
			case "1":
				m.findingFilter = filterVulnerability
			case "2":
				m.findingFilter = filterWarning
			case "3":
				m.findingFilter = filterInfo
			}
			m.scroll = 0
			return m, nil
		}
	case "x":
		if !m.inDetail && m.globalTab == tabHistory {
			m.requestClearHistoryConfirm()
			return m, nil
		}
	case "q":
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
