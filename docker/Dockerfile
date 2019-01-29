FROM alpine:latest as builder

RUN apk add --no-cache \
    autoconf \
    automake \
    bison \
    build-base \
    curl \
    flex \
    git \
    libmnl-dev \
    libtool \
    linux-headers \
    readline-dev \
    gdb pv strace valgrind vim  # for debug only

RUN mkdir -p \
    /baseroot/opt/wh/tools \
    /baseroot/usr/bin \
    /baseroot/usr/lib \
    /baseroot/usr/local/lib/lua/5.3 \
    /baseroot/usr/share/bash-completion/completions

WORKDIR /root
RUN git clone https://github.com/jedisct1/libsodium && \
    git clone  https://github.com/miniupnp/miniupnp && \
    curl -R -O http://www.tcpdump.org/release/libpcap-1.9.0.tar.gz && \
    curl -R -O https://www.lua.org/ftp/lua-5.3.5.tar.gz && \
    tar xfz libpcap-1.9.0.tar.gz && tar xfz lua-5.3.5.tar.gz

# Build libpcap
WORKDIR /root/libpcap-1.9.0
RUN ./configure && \
    make -j && \
    make install

# Build sodium
WORKDIR /root/libsodium
RUN git checkout stable && \
    ./autogen.sh && \
    ./configure && \
    make -j && \
    make install

# Build Lua
WORKDIR /root/lua-5.3.5
#RUN sed -i 's/MYCFLAGS=/MYCFLAGS=-g/g' src/Makefile && sed -i 's/-O2//g' src/Makefile
RUN make -j linux && \
    make install

# Build MiniUPNPc
WORKDIR /root/miniupnp/miniupnpc
RUN git checkout miniupnpc_2_1 && \
    make -j && \
    make install && \
    make install DESTDIR=/baseroot

# Build WireGuard tools
WORKDIR /root/wh/
COPY deps deps
WORKDIR /root/wh/deps/WireGuard/src/tools
RUN make -j && \
    make install DESTDIR=/baseroot

# Prepare wh
RUN printf "#!/bin/sh\nexport LUA_PATH=/opt/wh/?.lua\nlua /opt/wh/tools/cli.lua \$@\n" >> /baseroot/usr/bin/wh && \
    chmod +x /baseroot/usr/bin/wh

# Build WireHub
WORKDIR /root/wh
COPY Makefile .
COPY src src
RUN make -j && \
    cp src/*.lua /baseroot/opt/wh && \
    cp src/tools/*.lua /baseroot/opt/wh/tools && \
    cp .obj/*.so /baseroot/usr/local/lib/lua/5.3/

COPY config/* /baseroot/etc/wirehub/

WORKDIR /baseroot
RUN cp /usr/local/lib/*.so* usr/lib/ && \
    cp /usr/local/bin/lua* usr/bin && \
    tar cf /baseroot.tar .

##

FROM alpine:latest as wh

RUN apk add --no-cache \
    iptables \
    libmnl \
    readline

COPY --from=builder /baseroot.tar /
RUN tar xf /baseroot.tar && \
    rm /baseroot.tar && \
    rm -rf /usr/include/* /usr/share/man/* /usr/lib/*.a

