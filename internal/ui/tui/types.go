package tui

import (
	"sync"
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
type findingFilter int
type confirmAction int

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

const (
	filterAll findingFilter = iota
	filterVulnerability
	filterWarning
	filterInfo
)

const (
	confirmNone confirmAction = iota
	confirmNewScan
	confirmClearHistory
	confirmPauseResume
	confirmRestart
	confirmStop
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
	flags      string
	targets    []string
	status     string
	phase      string
	scanned    int64
	total      int64
	percent    int
	startedAt  time.Time
	endedAt    time.Time
	reportPath string
	donePath   string
	crawlPath  string
	pid        int
	lastEvent  string
	vulnCount  int
	warnCount  int
	infoCount  int
}

type model struct {
	width          int
	height         int
	target         string
	currentPhase   string
	scanned        int64
	total          int64
	startedAt      time.Time
	reportPath     string
	finished       bool
	globalTab      globalTab
	detailTab      detailTab
	inDetail       bool
	selectedScan   int
	detailScan     int
	scroll         int
	followLogs     bool
	statusMessage  string
	statusUntil    time.Time
	confirmAction  confirmAction
	confirmMessage string
	logs           []string
	findings       []findingItem
	targets        []string
	targetSeen     map[string]bool
	scans          []scanEntry
	history        []launchItem
	queue          []launchItem
	launchHost     string
	launchFlags    string
	action         actionMode
	focus          inputFocus
	findingFilter  findingFilter
	findingQuery   string
	findingSearch  bool
}
