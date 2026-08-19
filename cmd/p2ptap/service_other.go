//go:build !windows && !linux && !darwin

package main

import (
	"fmt"
	"os"
)

func checkAndRunService() bool {
	return false
}

func handleServiceCommand(args []string) {
	fmt.Println("The 'service' command is supported on Windows, Linux (systemd), and macOS (launchd).")
	os.Exit(1)
}
