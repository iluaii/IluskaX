package events

import (
	"io"
	"strings"
	"sync"
	"time"
)

type Type string

const (
	EventScanStarted   Type = "scan_started"
	EventScanFinished  Type = "scan_finished"
	EventPhaseStarted  Type = "phase_started"
	EventPhaseProgress Type = "phase_progress"
	EventLogMessage    Type = "log_message"
	EventFindingAdded  Type = "finding_added"
	EventSitemapAdded  Type = "sitemap_added"
	EventReportWritten Type = "report_written"
)

type Event struct {
	Type      Type
	Timestamp time.Time
	Source    string
	Message   string
	Phase     string
	Scanned   int64
	Total     int64
	Payload   map[string]string
}

type Emitter struct {
	mu          sync.RWMutex
	subscribers []chan Event
}

func NewEmitter() *Emitter {
	return &Emitter{}
}

func (e *Emitter) Publish(evt Event) {
	evt.Timestamp = time.Now()

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, ch := range e.subscribers {
		select {
		case ch <- evt:
		default:
		}
	}
}

func (e *Emitter) Subscribe(buffer int) <-chan Event {
	ch := make(chan Event, buffer)

	e.mu.Lock()
	e.subscribers = append(e.subscribers, ch)
	e.mu.Unlock()

	return ch
}

type Writer struct {
	target  io.Writer
	emitter *Emitter
	source  string
}

func NewWriter(target io.Writer, emitter *Emitter, source string) io.Writer {
	return &Writer{target: target, emitter: emitter, source: source}
}

func (w *Writer) Write(p []byte) (int, error) {
	n, err := w.target.Write(p)
	if w.emitter != nil && len(p) > 0 {
		msg := string(p)
		if strings.TrimSpace(msg) != "" {
			w.emitter.Publish(Event{
				Type:    EventLogMessage,
				Source:  w.source,
				Message: msg,
			})
		}
	}
	return n, err
}
