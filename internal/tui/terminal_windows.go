package tui

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func initPlatformTerminal() (func(), error) {
	input, output := windows.Handle(os.Stdin.Fd()), windows.Handle(os.Stdout.Fd())
	var inputMode, outputMode uint32
	hasInput := windows.GetConsoleMode(input, &inputMode) == nil
	hasOutput := windows.GetConsoleMode(output, &outputMode) == nil
	restore := func() {
		if hasInput {
			windows.SetConsoleMode(input, inputMode)
		}
		if hasOutput {
			windows.SetConsoleMode(output, outputMode)
		}
	}
	if hasOutput {
		if err := windows.SetConsoleMode(output, outputMode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
			return nil, fmt.Errorf("enable Windows terminal output: %w", err)
		}
	}
	if hasInput {
		mode := inputMode &^ (windows.ENABLE_LINE_INPUT | windows.ENABLE_ECHO_INPUT | windows.ENABLE_QUICK_EDIT_MODE)
		mode |= windows.ENABLE_VIRTUAL_TERMINAL_INPUT | windows.ENABLE_EXTENDED_FLAGS
		if err := windows.SetConsoleMode(input, mode); err != nil {
			restore()
			return nil, fmt.Errorf("enable Windows terminal input: %w", err)
		}
	}
	return restore, nil
}
