package P2PTap

import (
	"encoding/json"
	"fmt"

	"p2ptap/pkg/config"
)

func parseConfig(cfgJSON string) (*config.Config, error) {
	cfg := config.DefaultConfig()
	if cfgJSON != "" {
		if err := json.Unmarshal([]byte(cfgJSON), cfg); err != nil {
			return nil, fmt.Errorf("android: invalid config JSON: %w", err)
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("android: invalid config: %w", err)
	}
	if cfg.ExitNode.Enable {
		return nil, fmt.Errorf("android: exit node server is not supported on this build")
	}
	return cfg, nil
}

// ValidateConfig checks the same candidate as Start, without consuming a TUN
// descriptor, stopping the running node, or modifying its configuration.
func ValidateConfig(cfgJSON string) error {
	_, err := parseConfig(cfgJSON)
	return err
}

// NormalizePeerAddress validates an address for a static/bootstrap list.
func NormalizePeerAddress(address string) (string, error) {
	return config.NormalizePeerAddress(address)
}
