.PHONY: all build clean docker docker-sandbox docker-root1 run-docker run-sandbox

SO = .obj/whcore.so
SRC_C = $(wildcard src/core/*.c)
OBJ_C = $(patsubst src/core/%.c,.obj/%.o,$(SRC_C)) .obj/embeddable-wg.o

EMBED_WG_PATH = deps/WireGuard/contrib/examples/embeddable-wg-library

CC=gcc
MINIMAL_CFLAGS=-Wall -fPIC
DEBUG?=n

ifeq ($(DEBUG), y)
	MINIMAL_CFLAGS+=-g
else
	MINIMAL_CFLAGS+=-O2
endif

CFLAGS=$(MINIMAL_CFLAGS) -Wextra -Ideps/WireGuard/contrib/examples/embeddable-wg-library
WG_EMBED_CFLAGS=$(MINIMAL_CFLAGS)
LDFLAGS=-lsodium -lpthread -lpcap -lminiupnpc

all: build

build: $(SO)

$(SO): $(OBJ_C)
	$(CC) -shared -o $@ $(OBJ_C) $(LDFLAGS)
ifeq ($(DEBUG), n)
	strip $@
endif
	@ls -lh $@

.obj/embeddable-wg.o: $(EMBED_WG_PATH)/wireguard.c
	$(CC) -c $< -o $@ $(WG_EMBED_CFLAGS)

.obj/%.o: src/core/%.c
	@mkdir -p .obj
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -f $(SO) $(OBJ_C)

docker:
	docker build -t wirehub/wh -f docker/Dockerfile .

docker-sandbox:
	docker build --target builder -t wirehub/builder -f docker/Dockerfile .
	docker build -t wirehub/sandbox -f docker/Dockerfile.sandbox .

docker-root1: docker
	docker build --no-cache=true -t wirehub/root1 -f docker/Dockerfile.root1 .

run-docker:
	docker run -it --rm --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add SYS_PTRACE wirehub /bin/sh

run-sandbox:
	docker run -it --rm --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add SYS_PTRACE -v "$(shell pwd):/root/wh" wirehub/sandbox /bin/bash

