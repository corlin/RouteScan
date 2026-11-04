// internal/tui/screen.go
package tui

import (
	"fmt"
)

// EnterAltScreen switches to the alternate screen buffer, clears it, and hides the cursor.
func EnterAltScreen() {
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
