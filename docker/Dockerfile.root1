FROM wirehub/wh:latest

RUN apk add --no-cache \
    bash \
    bash-completion

WORKDIR /opt/wh

RUN nc 172.17.0.1 1324 > ./sk

RUN echo "lua src/sink-udp.lua &" >> ./run-root1.sh && \
    echo "FG=y LOG=2 wh up /etc/wirehub/public private-key ./sk mode direct" >> ./run-root1.sh && \
    chmod +x ./run-root1.sh

RUN wh completion get-bash > /usr/share/bash-completion/completions/wh

ENTRYPOINT ./run-root1.sh

