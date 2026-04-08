package ui

import (
	"io"
	"os"

	"IluskaX/internal/events"
	"IluskaX/internal/ui/tui"
)

type Mode string

const (
	ModeCLI Mode = "cli"
	ModeTUI Mode = "tui"
)

type Session struct {
	mode    Mode
	out     io.Writer
	emitter *events.Emitter
	status  *StatusBar
	reports *ReportCollector
	tuiApp  *tui.App
}

func ParseMode(raw string) Mode {
	switch raw {
	case string(ModeTUI):
		return ModeTUI
	default:
		return ModeCLI
	}
}

func NewSession(mode Mode, out io.Writer) *Session {
	if out == nil {
		out = os.Stdout
	}
	emitter := events.NewEmitter()
	sess := &Session{
		mode:    mode,
		out:     out,
		emitter: emitter,
		status:  NewStatusBarWithEmitter(out, emitter),
		reports: NewReportCollectorWithEmitter(emitter),
	}
	if mode == ModeTUI {
		sess.status.SetSilent(true)
		sess.tuiApp = tui.New(emitter)
	}
	return sess
}

func (s *Session) Start() {
	if s == nil {
		return
	}
	s.status.Start()
	if s.mode == ModeTUI && s.tuiApp != nil {
		s.tuiApp.Start()
	}
}

func (s *Session) Stop() {
	if s == nil {
		return
	}
	if s.mode == ModeTUI && s.tuiApp != nil {
		s.tuiApp.Stop()
	}
	s.status.Stop()
}

func (s *Session) Mode() Mode {
	return s.mode
}

func (s *Session) Emitter() *events.Emitter {
	return s.emitter
}

func (s *Session) StatusBar() *StatusBar {
	return s.status
}

func (s *Session) Reports() *ReportCollector {
	return s.reports
}

func (s *Session) Writer(source string) io.Writer {
	target := s.out
	if s.mode == ModeTUI {
		target = io.Discard
	}
	return events.NewWriter(target, s.emitter, source)
}
