package web

import (
	"sync"
	"sync/atomic"

	"p2ptap/pkg/config"
)

// Both HTTP entry points share the saved snapshot. The startup baseline stays
// fixed so another save cannot erase a still-pending restart requirement.
type webConfigState struct {
	mu      sync.Mutex
	startup *config.Config
	saved   atomic.Pointer[config.Config]
}

func configStateFor(collector *StatsCollector, cfg *config.Config) *webConfigState {
	state := &webConfigState{}
	if collector != nil {
		state = &collector.configState
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.startup == nil && cfg != nil {
		state.startup = cfg
		state.saved.Store(cfg)
	}
	return state
}

// Persist before publication. Embedded clients can provide their own durable
// storage instead of a config.json file. A failed save leaves both the saved
// and runtime snapshots intact.
func persistWebConfig(collector *StatsCollector, path string, cfg *config.Config) error {
	if collector != nil && collector.PersistConfig != nil {
		return collector.PersistConfig(cfg)
	}
	return config.UpdateConfigFileDelta(path, cfg)
}

func (s *Server) persistConfig(path string, cfg *config.Config) error {
	persist := *cfg
	// Generated tokens belong in their private startup sidecar, not config.json.
	if s.authTokenAuto {
		persist.WebUI.AuthToken = ""
	}
	return persistWebConfig(s.collector, path, &persist)
}

func configSaveResponse(restartFields []string) map[string]interface{} {
	message := "Configuration saved and applied successfully"
	if len(restartFields) > 0 {
		message = "Configuration saved; restart required for pending fields"
	}
	return map[string]interface{}{
		"status": "ok", "message": message,
		"restart_required": len(restartFields) > 0,
		"restart_fields":   restartFields,
	}
}
