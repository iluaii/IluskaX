package tui

import (
	"fmt"
	"os"
	"time"

	"IluskaX/internal/events"

	tea "github.com/charmbracelet/bubbletea"
)

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
		history:    loadPersistedHistory(),
		queue:      make([]launchItem, 0, 16),
		action:     actionRunNow,
		followLogs: true,
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
