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
VERSION := $(shell git describe --tags --abbrev=0)
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

BRANCH := $(shell git symbolic-ref --short HEAD)
build-integration:
	@ git stash save
	$(GO) build -ldflags "$(LDFLAGS)" -o integration/go-cti.new
	git checkout $(shell git describe --tags --abbrev=0)
	@git reset --hard
	$(GO) build -ldflags "$(LDFLAGS)" -o integration/go-cti.old
	git checkout $(BRANCH)
	-@ git stash apply stash@{0} && git stash drop stash@{0}

clean-integration:
	-pkill go-cti.old
	-pkill go-cti.new
	-rm integration/go-cti.old integration/go-cti.new integration/go-cti.old.sqlite3 integration/go-cti.new.sqlite3
	-rm -rf integration/diff
	-docker kill redis-old redis-new
	-docker rm redis-old redis-new

fetch-rdb:
	integration/go-cti.old fetch threat --dbpath=integration/go-cti.old.sqlite3
	integration/go-cti.new fetch threat --dbpath=integration/go-cti.new.sqlite3

fetch-redis:
	docker run --name redis-old -d -p 127.0.0.1:6379:6379 redis
	docker run --name redis-new -d -p 127.0.0.1:6380:6379 redis

	integration/go-cti.old fetch threat --dbtype redis --dbpath "redis://127.0.0.1:6379/0"
	integration/go-cti.new fetch threat --dbtype redis --dbpath "redis://127.0.0.1:6380/0"

diff-cves:
	@ python integration/diff_server_mode.py cves --sample_rate 0.01
	@ python integration/diff_server_mode.py multi-cves --sample_rate 0.01

diff-server-rdb:
	integration/go-cti.old server --dbpath=integration/go-cti.old.sqlite3 --port 1325 > /dev/null 2>&1 & 
	integration/go-cti.new server --dbpath=integration/go-cti.new.sqlite3 --port 1326 > /dev/null 2>&1 &
	make diff-cves
	pkill go-cti.old 
	pkill go-cti.new

diff-server-redis:
	integration/go-cti.old server --dbtype redis --dbpath "redis://127.0.0.1:6379/0" --port 1325 > /dev/null 2>&1 & 
	integration/go-cti.new server --dbtype redis --dbpath "redis://127.0.0.1:6380/0" --port 1326 > /dev/null 2>&1 &
	make diff-cves
	pkill go-cti.old 
	pkill go-cti.new

diff-server-rdb-redis:
	integration/go-cti.new server --dbpath=integration/go-cti.new.sqlite3 --port 1325 > /dev/null 2>&1 &
	integration/go-cti.new server --dbtype redis --dbpath "redis://127.0.0.1:6380/0" --port 1326 > /dev/null 2>&1 &
	make diff-cves
	pkill go-cti.new