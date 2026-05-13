BINARY  := slate
MODULE  := github.com/bigblue-r4/slate
CMD     := ./cmd/slate
GOFLAGS := -trimpath -ldflags="-s -w"

.PHONY: all build install clean tidy test

all: build

build:
	go build $(GOFLAGS) -o $(BINARY) $(CMD)

install: build
	install -m 0755 $(BINARY) /usr/local/bin/$(BINARY)

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)

test:
	go test ./...
