// internal/tui/screen.go
package tui

import (
	"fmt"
	"sync"
)

var terminalMu sync.Mutex
var restoreModes func()
var alternateScreen bool

func InitTerminal() error {
	terminalMu.Lock()
	defer terminalMu.Unlock()
	if restoreModes != nil {
		return nil
	}
	var err error
	restoreModes, err = initPlatformTerminal()
	return err
}

// EnterAltScreen switches to the alternate screen buffer, clears it, and hides the cursor.
func EnterAltScreen() {
	terminalMu.Lock()
	alternateScreen = true
	terminalMu.Unlock()
	fmt.Print("\033[?1049h\033[H\033[?25l")
}

// ExitAltScreen restores cursor visibility and exits the alternate screen buffer.
func ExitAltScreen() {
	fmt.Print("\033[?25h\033[?1049l")
}

// ClearScreen clears the terminal screen and positions the cursor at row 1, col 1.
func ClearScreen() {
	fmt.Print("\033[2J\033[H")
}

// RestoreTerminal restores terminal echo, canonical mode, cursor visibility,
// and exits the alternate screen buffer safely across platforms.
func RestoreTerminal() {
	terminalMu.Lock()
	defer terminalMu.Unlock()
	if alternateScreen {
		ExitAltScreen()
		alternateScreen = false
	}
	if restoreModes != nil {
		restoreModes()
		restoreModes = nil
	}
}
