// internal/tui/keypress.go
package tui

import (
	"os"
	"os/exec"
	"runtime"
)

type KeyType int

const (
	KeyNone KeyType = iota
	KeyUp
	KeyDown
	KeyProxyToggle
	KeyRefresh
	KeySnapshot
	KeyQuit
)

// parseKey translates raw byte sequences into KeyType values.
func parseKey(buf []byte, n int) KeyType {
	if n == 1 {
		switch buf[0] {
		case 'q', 'Q', 3: // 'q' or Ctrl+C
			return KeyQuit
		case 'p', 'P':
			return KeyProxyToggle
		case 'r', 'R':
			return KeyRefresh
		case 's', 'S':
			return KeySnapshot
		case 'j', 'J':
			return KeyDown
		case 'k', 'K':
			return KeyUp
		}
	} else if n == 3 && buf[0] == 27 && (buf[1] == 91 || buf[1] == 79) { // \033[ or \033O
		switch buf[2] {
		case 'A':
			return KeyUp
		case 'B':
			return KeyDown
		}
	}
	return KeyNone
}

// ListenKeys configures terminal raw mode and listens for user key presses,
// dispatching KeyType events over keyChan until stopChan is signaled or terminal exits.
func ListenKeys(keyChan chan<- KeyType, stopChan <-chan struct{}) {
	// macOS uses -f /dev/tty, Linux uses -F /dev/tty
	sttyFlag := "-f"
	if runtime.GOOS == "linux" {
		sttyFlag = "-F"
	}

	exec.Command("stty", sttyFlag, "/dev/tty", "cbreak", "min", "1").Run()
	exec.Command("stty", sttyFlag, "/dev/tty", "-echo").Run()
	defer exec.Command("stty", sttyFlag, "/dev/tty", "echo").Run()

	buf := make([]byte, 3)
	for {
		select {
		case <-stopChan:
			return
		default:
			n, err := os.Stdin.Read(buf)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}

			key := parseKey(buf, n)
			if key != KeyNone {
				select {
				case keyChan <- key:
					if key == KeyQuit {
						return
					}
				case <-stopChan:
					return
				}
			}
		}
	}
}
