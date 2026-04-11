GO=go
BINARY=webscan

.PHONY: tidy build test vet run

tidy:
	$(GO) mod tidy

vet:
	$(GO) vet ./...

test:
	$(GO) test ./... -v

build:
	$(GO) build -o $(BINARY) ./...

run:
	$(GO) run main.go $(ARGS)

release:
	@echo "Building release artifacts in ./dist"
	mkdir -p dist
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags='-s -w' -o dist/$(BINARY)-linux-amd64 .
	GOOS=windows GOARCH=amd64 $(GO) build -ldflags='-s -w' -o dist/$(BINARY)-windows-amd64.exe .
	GOOS=darwin GOARCH=amd64 $(GO) build -ldflags='-s -w' -o dist/$(BINARY)-darwin-amd64 .
