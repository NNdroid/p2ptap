//go:build !linux || android
// +build !linux android

package tap

import (
	"context"
	"errors"
)

// NewEpollPoller always returns an error on non-Linux platforms; the caller
// must fall back to timer-based polling.
func NewEpollPoller(dev TAPDevice) (*EpollPoller, error) {
	return nil, errors.New("epoll not supported on this platform")
}

// Wait is a stub for non-Linux platforms.
func (p *EpollPoller) Wait(ctx context.Context) error {
	return errors.New("epoll not supported on this platform")
}

// NotifyOnCancel is a stub for non-Linux platforms.
func (p *EpollPoller) NotifyOnCancel(ctx context.Context) {}

// Close is a stub for non-Linux platforms.
func (p *EpollPoller) Close() error {
	return nil
}
