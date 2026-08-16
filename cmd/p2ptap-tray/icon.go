//go:build windows
// +build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	procCreateIcon = moduser32.NewProc("CreateIcon")
)

// generateStatusIcon creates a 32x32 Win32 HICON dynamically in memory featuring a cute, chubby, rounded cartoon goose
// status: "green" (connected), "yellow" (relay/connecting), "red" (disconnected/error), "blue" (exit node active)
func generateStatusIcon(status string) syscall.Handle {
	const width = 32
	const height = 32

	andBits := make([]byte, width*height/8) // 128 bytes mask
	xorBits := make([]byte, width*height*4) // 4096 bytes RGBA

	// Background circle color based on status
	var bgR, bgG, bgB byte
	switch status {
	case "green":
		bgR, bgG, bgB = 0x10, 0xb9, 0x81 // Emerald Green
	case "yellow":
		bgR, bgG, bgB = 0xf5, 0x9e, 0x0b // Amber Gold
	case "blue":
		bgR, bgG, bgB = 0x3b, 0x82, 0xf6 // Blue (exit node active)
	case "red":
		bgR, bgG, bgB = 0xef, 0x44, 0x44 // Red
	default:
		bgR, bgG, bgB = 0x06, 0xb6, 0xd4 // Cyan
	}

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			pixelIdx := (y*width + x) * 4
			bitIdx := y*width + x
			byteIdx := bitIdx / 8
			bitOffset := 7 - (bitIdx % 8)

			dxBg := x - 16
			dyBg := y - 16
			distSqBg := dxBg*dxBg + dyBg*dyBg

			if distSqBg > 15*15 {
				// Outside background circle -> Transparent
				andBits[byteIdx] |= (1 << bitOffset)
				continue
			}

			// Base background circle
			r, g, b, a := bgR, bgG, bgB, byte(255)

			// 1. Chubby Goose Body (lower plump circle)
			dxBody := x - 15
			dyBody := y - 19
			distSqBody := dxBody*dxBody + dyBody*dyBody

			// 2. Chubby Goose Head (upper round circle)
			dxHead := x - 14
			dyHead := y - 11
			distSqHead := dxHead*dxHead + dyHead*dyHead

			// 3. Orange Beak
			dxBeak := x - 21
			dyBeak := y - 12
			distSqBeak := dxBeak*dxBeak + dyBeak*dyBeak

			// 4. Cute Eye
			dxEye := x - 17
			dyEye := y - 10
			distSqEye := dxEye*dxEye + dyEye*dyEye

			if distSqEye <= 1 {
				// Eye: Black
				r, g, b = 15, 23, 42
			} else if distSqBeak <= 5 && x >= 19 {
				// Beak: Bright Orange
				r, g, b = 249, 115, 22
			} else if distSqHead <= 28 || distSqBody <= 55 {
				// Chubby Goose Feather Body/Head: Pure Soft White
				r, g, b = 255, 255, 255
			} else if distSqBg > 14*14 {
				// Smooth outer ring border
				a = 180
			}

			xorBits[pixelIdx+0] = b
			xorBits[pixelIdx+1] = g
			xorBits[pixelIdx+2] = r
			xorBits[pixelIdx+3] = a
		}
	}

	hInstance, _, _ := procGetModuleHandleW.Call(0)
	hIcon, _, _ := procCreateIcon.Call(
		hInstance,
		uintptr(width),
		uintptr(height),
		1,  // Planes
		32, // Bits per pixel
		uintptr(unsafe.Pointer(&andBits[0])),
		uintptr(unsafe.Pointer(&xorBits[0])),
	)

	return syscall.Handle(hIcon)
}
