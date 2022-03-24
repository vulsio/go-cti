.PHONY: \
	build \
	install \
	all \
	vendor \
	lint \
	vet \
	fmt \
	fmtcheck \
	pretest \
	test \
	cov \
	clean

SRCS = $(shell git ls-files '*.go')
PKGS = $(shell go list ./...)
REVISION := $(shell git rev-parse --short HEAD)
BUILDTIME := $(shell date "+%Y%m%d_%H%M%S")
LDFLAGS := -X 'github.com/vulsio/go-cti/config.Version=$(VERSION)' \
	-X 'github.com/vulsio/go-cti/config.Revision=$(REVISION)'
GO := GO111MODULE=on go

all: build test

build: main.go
	$(GO) build -a -ldflags "$(LDFLAGS)" -o go-cti $<

install: main.go
	$(GO) install -ldflags "$(LDFLAGS)"

lint:
	$(GO) install github.com/mgechev/revive@latest
	revive -config ./.revive.toml -formatter plain $(PKGS)

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
