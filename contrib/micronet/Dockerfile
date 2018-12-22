FROM alpine:latest as builder

RUN apk add --no-cache \
    build-base \
    linux-headers \
    lua5.3-dev \
    python3

WORKDIR /root
COPY scripts scripts
COPY src src
COPY Makefile Makefile

RUN make

FROM alpine:latest as micronet

RUN apk add --no-cache \
    lua5.3

COPY --from=builder /root/bin/micronet /usr/local/bin

