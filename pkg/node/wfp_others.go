//go:build !windows

package node

type WFPManager struct{}

var globalWFPManager = &WFPManager{}

func GetWFPManager() *WFPManager {
	return globalWFPManager
}

func (w *WFPManager) EnableProcessBypass() error {
	return nil
}

func (w *WFPManager) DisableProcessBypass() error {
	return nil
}
