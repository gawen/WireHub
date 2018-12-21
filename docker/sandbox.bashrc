export PS1='\u@\h:\W \$ '
source /etc/profile.d/bash_completion.sh

alias t="wh-sandbox-test"

if [ ! -f /dev/net/tun ]; then
    mkdir /dev/net
	mknod /dev/net/tun c 10 200
fi

function compile_micronet() {
    cp -r contrib/micronet /tmp
    (cd /tmp/micronet && make clean && make)
    cp /tmp/micronet/bin/micronet /usr/local/bin
}

clear
echo "#####################"
echo "# wirehub's sandbox #"
echo "#####################"
echo ""


if [ ! -z "$MICRONET" ]; then
    if [ -z "$MICRONET_SERVER" ]; then
        export MICRONET_SERVER=172.17.0.1
    fi

    echo "µnet is enabled, node is $MICRONET, server is $MICRONET_SERVER"
    compile_micronet
    UNET_SERVERNAME=$MICRONET_SERVER micronet client $MICRONET &
fi

if [ ! -z "$ROOT" ]; then
    echo "start root"
    echo $ROOT > /tmp/sk
    lua src/sink-udp.lua &
    wh up public private-key /tmp/sk mode direct &

elif [ ! -z "$T" ]; then
    if [ ! -f "tests/keys/config" ]; then
        wh-sandbox-test -1
        exit -1
    fi
    echo "start test node $T"
    wh-sandbox-test $T &
fi

