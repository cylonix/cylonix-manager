all: build
	@echo "build finished"

APP_DIR := manager
APP_NAME := cylonix-manager

all: build

init:
	git submodule update --init

build: force
	go build -o $(APP_NAME) $(APP_DIR)/main.go

examples: force
	go build -o build/wg_client examples/wg_client/main.go

clean: force
	rm $(APP_NAME)

generate: ipdrawer-api supervisor-api wg-api manager-api fw-api
	@echo "\033[0;32mGenerated all api's successfully\033[0m"
	go mod tidy

manager-api:
	sudo rm -rf api/v2/
	-mkdir -p api/v2/models
	@echo "Generating manager api server code"
	oapi-codegen --config=api/server.cfg.yaml submodules/openapi/manager/openapi-3.0.yaml
	oapi-codegen --config=api/model.cfg.yaml  submodules/openapi/manager/openapi-3.0.yaml
	@echo "\033[0;32mGenerated manager api server code successfully\033[0m"

wg-api:
	sudo rm -rf clients/wg
	mkdir -p clients/wg
	@echo "Generating wireguard agent api client code"
	./submodules/openapi/scripts/client.sh \
		submodules/openapi/wg/wg.yaml \
		clients/wg wg_agent 1.0.0
	@echo "\033[0;32mGenerated wg api's successfully\033[0m"

supervisor-api:
	sudo rm -rf clients/supervisor
	mkdir -p clients/supervisor
	@echo "Generating supervisor api client code"
	./submodules/openapi/scripts/client.sh \
		submodules/openapi/supervisor/openapi-2.0.yaml \
		clients/supervisor supervisor 1.0.0
	@echo "\033[0;32mGenerated sase-supervisor api's successfully\033[0m"

ipdrawer-api:
	sudo rm -rf clients/ipdrawer
	mkdir -p clients/ipdrawer
	@echo "Generating ip drawer api client code"
	./submodules/openapi/scripts/client.sh \
		submodules/openapi/ipdrawer/ipdrawer.yaml \
		clients/ipdrawer ipdrawer 1.0.0
	@echo "\033[0;32mGenerated ipdrawer api's successfully\033[0m"

fw-api:
	sudo rm -rf clients/fw
	mkdir -p clients/fw
	@echo "Generating sase-fw api client code"
	./submodules/openapi/scripts/client.sh \
		submodules/openapi/fw/openapi.yaml \
		clients/fw fw 1.0.0
	@echo "\033[0;32mGenerated fw api's successfully\033[0m"

.PHONY: force generate-api
force:;

test:
	go test ./daemon/... -cover -count=1
	go test ./pkg/hua/... -cover -count=1
	go test ./pkg/resources/... -cover -count=1
	rm ./daemon/test.db ./daemon/database/test.db ./pkg/hua/test.db

.PHONY: alpine docker
RELEASE?=v1.0
VERSION:=$(shell git describe --tags --exact-match 2> /dev/null || \
				git rev-parse --short HEAD || echo "unknown")
REVISION:=$(shell git rev-parse HEAD)
GIT_VERSION := $(shell if [ -d ".git" ]; then git version; fi 2>/dev/null)
ifdef GIT_VERSION
    GIT_HASH = $(shell git rev-parse --verify HEAD)
endif

docker: alpine
alpine:
	docker build  \
		--network host \
		-f docker/Dockerfile.$@ \
		--tag cylonix/${APP_NAME}:$@-$(VERSION) \
		--tag cylonix/${APP_NAME}:$@-$(RELEASE) \
		--tag cylonix/${APP_NAME}:$@-latest \
		--build-arg VERSION_LONG=${VERSION} \
		--build-arg VERSION_SHORT=${RELEASE} \
		--build-arg VERSION_GIT_HASH=${GIT_HASH} \
		--build-arg GOPROXY=${GOPROXY} \
		.
