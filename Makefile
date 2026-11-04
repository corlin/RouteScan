BINARY=routescan
GO?=/opt/homebrew/bin/go

all: build

build:
	$(GO) build -o $(BINARY) cmd/routescan/main.go

test:
	$(GO) test -v ./...

clean:
	rm -f $(BINARY) routescan_*.md test_report.md
