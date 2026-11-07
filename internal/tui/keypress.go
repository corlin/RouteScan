// internal/tui/keypress.go
package tui

import (
	"bufio"
	"os"
	"strings"
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
	buf = []byte(strings.TrimRight(string(buf[:n]), "\r\n"))
	n = len(buf)
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
	reader := bufio.NewReader(os.Stdin)
	escapeState := 0
	for {
		select {
		case <-stopChan:
			return
		default:
			b, err := reader.ReadByte()
			if err != nil {
				return
			}
			// Decode incrementally so split arrow sequences work, while a lone
			// Escape never consumes the next ordinary command (especially q).
			if b == 27 {
				escapeState = 1
				continue
			}
			if escapeState == 1 && (b == '[' || b == 'O') {
				escapeState = 2
				continue
			}
			key := KeyNone
			if escapeState == 2 && (b == 'A' || b == 'B') {
				key = parseKey([]byte{27, '[', b}, 3)
			} else {
				key = parseKey([]byte{b}, 1)
			}
			escapeState = 0
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
