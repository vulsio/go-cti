.PHONY: \
	build \
	install \
	all \
	vendor \
	lint \
	golangci \
	vet \
	fmt \
	fmtcheck \
	pretest \
	test \
	cov \
	clean

SRCS = $(shell git ls-files '*.go')
PKGS = $(shell go list ./...)
VERSION := $(shell git describe --tags --abbrev=0)
REVISION := $(shell git rev-parse --short HEAD)
BUILDTIME := $(shell date "+%Y%m%d_%H%M%S")
LDFLAGS := -X 'github.com/vulsio/go-cti/config.Version=$(VERSION)' \
	-X 'github.com/vulsio/go-cti/config.Revision=$(REVISION)'
GO := CGO_ENABLED=0 go

all: build test

build: main.go
	$(GO) build -a -ldflags "$(LDFLAGS)" -o go-cti $<

install: main.go
	$(GO) install -ldflags "$(LDFLAGS)"

lint:
	go install github.com/mgechev/revive@latest
	revive -config ./.revive.toml -formatter plain $(PKGS)

golangci:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run

vet:
	echo $(PKGS) | xargs env $(GO) vet || exit;

fmt:
	gofmt -w $(SRCS)

fmtcheck:
	$(foreach file,$(SRCS),gofmt -d $(file);)

pretest: lint vet fmtcheck

test: pretest
	$(GO) test -cover -v ./... || exit;

cov:
	@ go get -v github.com/axw/gocov/gocov
	@ go get golang.org/x/tools/cmd/cover
	gocov test | gocov report

clean:
	$(foreach pkg,$(PKGS),go clean $(pkg) || exit;)
