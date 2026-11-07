package tui

import (
	"os"
	"testing"
)

func TestParseKeyWindowsLineEndings(t *testing.T) {
	for _, input := range []string{"q\r\n", "q\r", "q\n"} {
		if got := parseKey([]byte(input), len(input)); got != KeyQuit {
			t.Errorf("%q: got %v, want quit", input, got)
		}
	}
}

func TestListenKeysEscapeDoesNotSwallowQuit(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	originalStdin := os.Stdin
	os.Stdin = reader
	defer func() { os.Stdin = originalStdin }()
	if _, err := writer.Write([]byte{27, 'q'}); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	keys := make(chan KeyType, 2)
	ListenKeys(keys, make(chan struct{}))
	select {
	case key := <-keys:
		if key != KeyQuit {
			t.Fatalf("got %v, want quit", key)
		}
	default:
		t.Fatal("Escape swallowed the following quit key")
	}
}
