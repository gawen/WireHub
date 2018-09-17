#!/bin/sh
make /dev/net/tun
make
UNET_SERVERNAME=172.17.0.1 ./bin/micronet client $1
