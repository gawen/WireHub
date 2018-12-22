.PHONY: all clean run-server vgd-server docker

MICRONET=bin/micronet
SRC=$(wildcard src/*.c) obj/server.lua.c
HDR=$(wildcard src/*.h)

CFLAGS=-Wall -Wextra -g -llua -I/usr/include/lua5.3 -L/usr/lib/lua5.3

all: $(MICRONET)

/dev/net/tun:
	mkdir /dev/net
	mknod /dev/net/tun c 10 200

obj/server.lua.c: src/server.lua scripts/file2buf.py
	@mkdir -p obj
	luac5.3 -o obj/server.luac src/server.lua
	scripts/file2buf.py obj/server.luac _luacode_server > obj/server.lua.c

$(MICRONET): $(SRC) $(HDR)
	@mkdir -p bin
	$(CC) -o $(MICRONET) $(SRC) $(CFLAGS)

docker:
	docker build -t wirehub/micronet .

clean:
	rm -rf obj bin

run-server: $(MICRONET) /dev/net/tun
	$(MICRONET) server examples/conf.lua

gdb-server: $(MICRONET) /dev/net/tun
	gdb -ex run -args $(MICRONET) server examples/conf.lua

vgd-server: $(MICRONET) /dev/net/tun
	valgrind $(MICRONET) server examples/conf.lua

