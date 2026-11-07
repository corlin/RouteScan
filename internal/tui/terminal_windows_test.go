package tui

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// Execute the compiled test binary in a console to exercise real mode changes;
// go test normally redirects the test process's standard handles to pipes.
func TestWindowsTerminalRestoresModes(t *testing.T) {
	in, out := windows.Handle(os.Stdin.Fd()), windows.Handle(os.Stdout.Fd())
	var beforeIn, beforeOut uint32
	if windows.GetConsoleMode(in, &beforeIn) != nil || windows.GetConsoleMode(out, &beforeOut) != nil {
		t.Skip("requires an attached Windows console")
	}
	defer RestoreTerminal()
	if err := InitTerminal(); err != nil {
		t.Fatal(err)
	}
	var actualIn, actualOut uint32
	if err := windows.GetConsoleMode(in, &actualIn); err != nil {
		t.Fatal(err)
	}
	if err := windows.GetConsoleMode(out, &actualOut); err != nil {
		t.Fatal(err)
	}
	if actualIn&(windows.ENABLE_LINE_INPUT|windows.ENABLE_ECHO_INPUT) != 0 || actualIn&windows.ENABLE_VIRTUAL_TERMINAL_INPUT == 0 {
		t.Fatalf("input isn't in immediate VT mode: %#x", actualIn)
	}
	if actualOut&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING == 0 {
		t.Fatal("VT output disabled")
	}
	RestoreTerminal()
	windows.GetConsoleMode(in, &actualIn)
	windows.GetConsoleMode(out, &actualOut)
	if actualIn != beforeIn || actualOut != beforeOut {
		t.Fatalf("console modes not restored: input %#x -> %#x, output %#x -> %#x", beforeIn, actualIn, beforeOut, actualOut)
	}
}
