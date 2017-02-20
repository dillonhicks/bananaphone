SHELL ?= /usr/bin/env bash

keyfile ?=''

PEM_HEADER='BEGIN RSA PRIVATE KEY'
IMAGE_NAME=safelyusesshkeyexample

.PHONY: build

# Execute a docker build with tmpfs (--shm-size=64m [default]) which
# is ephemeral and will only last the lifetime of the build
build:
	$(MAKE) docker

docker:
	[ -z "$(keyfile)" ] && \
		(echo 'error: no keyfile specified!\n'; \
		 echo 'usage: make keyfile=<ssh-key-path> build\n'; \
		 false) || (true) && \
	docker build \
		--no-cache \
		--network=host \
		--build-arg CREDENTIALS_PORT=$(shell bananaphone -f $(keyfile) < /dev/null) \
		-t $(IMAGE_NAME) -f Dockerfile .


MATCHES=$(shell docker history --no-trunc $(IMAGE_NAME) | grep --color -i $(PEM_HEADER))
test-history:
	@[ -z "$(MATCHES)" ] && \
		(echo 'RSA Header in History: No' && exit 0) || \
		(echo "Failure!\n $(MATCHES)" && exit 1)


TMPFS_FILES=$(shell docker run --rm -it $(IMAGE_NAME) ls -1 /dev/shm)
test-image:
	@[ -z "$(TMPFS_FILES)" ] && \
		(echo 'Dangling tmpfs files: No' && exit 0) || \
		(echo "Failure!\n $(TMPFS_FILES)" && exit 1)


test: test-image test-history
	@echo 'Success!'
