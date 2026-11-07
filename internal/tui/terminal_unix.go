//go:build !windows

package tui

import (
	"os/exec"
	"runtime"
	"strings"
)

func initPlatformTerminal() (func(), error) {
	flag := "-f"
	if runtime.GOOS == "linux" {
		flag = "-F"
	}
	out, err := exec.Command("stty", flag, "/dev/tty", "-g").Output()
	if err != nil {
		return func() {}, nil
	} // redirected input
	if err := exec.Command("stty", flag, "/dev/tty", "cbreak", "min", "1", "-echo").Run(); err != nil {
		return nil, err
	}
	return func() { exec.Command("stty", flag, "/dev/tty", strings.TrimSpace(string(out))).Run() }, nil
}
