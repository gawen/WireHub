FROM wirehub/builder:latest

RUN (cd /baseroot && tar cf - .) | (cd / && tar xf -) && \
    rm -r /baseroot /opt /usr/local/lib/lua/5.3/whcore.so /usr/bin/wh && \
    printf "#!/bin/sh\nexport LUA_PATH=/root/wh/src/?.lua\nlua /root/wh/src/tools/cli.lua \$@\n" >> /usr/bin/wh && \
    chmod +x /usr/bin/wh

RUN apk add --no-cache \
    bash \
    bash-completion \
    bmon \
    build-base \
    curl \
    gdb \
    git \
    iptables \
    linux-headers \
    mtr \
    pv \
    strace \
    tcpdump \
    valgrind \
    vim

ENV DEBUG y
ENV LUA_PATH "/root/wh/src/?.lua"
ENV LUA_CPATH "/root/wh/.obj/?.so"
ENV PATH "/root/wh/docker:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

ENV WH_EXPERIMENTAL_MODIFY_HOSTS true

RUN ln -s /root/wh/docker/sandbox.bashrc /root/.bashrc
RUN wh completion get-bash > /usr/share/bash-completion/completions/wh

WORKDIR /root/wh
COPY docker docker

