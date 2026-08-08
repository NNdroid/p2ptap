//go:build !linux && !windows && !darwin

package node

func protectSocketOS(fd uintptr, wanIfName string) error {
	return nil
}
