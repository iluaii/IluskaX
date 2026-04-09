package tui

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type historyStore struct {
	History []launchItem `json:"history"`
}

func historyStorePath() string {
	return filepath.Join("Poutput", "tui_history.json")
}

func loadPersistedHistory() []launchItem {
	data, err := os.ReadFile(historyStorePath())
	if err != nil {
		return nil
	}
	var store historyStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil
	}
	return store.History
}

func savePersistedHistory(history []launchItem) error {
	if err := os.MkdirAll("Poutput", 0755); err != nil {
		return err
	}
	store := historyStore{History: history}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(historyStorePath(), data, 0644)
}

func (m *model) persistHistory() {
	if m == nil {
		return
	}
	_ = savePersistedHistory(m.history)
}

func (m *model) clearHistory() {
	if m == nil {
		return
	}
	m.history = nil
	m.queue = nil
	_ = os.Remove(historyStorePath())
}
