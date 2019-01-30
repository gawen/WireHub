# WireHub

WireHub (in a shell, *wh*) builds decentralized, peer-to-peer and secure overlay
networks. It is small (<10KLOC) and tends to be simple-to-use and easily
extendable.

It is built upon [WireGuard tunnels][wireguard] and provides distributed peer
discovery & routing capabilities, NAT trasversal, extendable name resolving, ...

⚠️ **Not ready for production!** This is still a work-in-progress. It still
requires some work to be clean and secure. The current code is provided for
testing only.

## Features

- **Single file network description**: a configuration of a network is a list
  of the public key, private IPs and hostnames for each node.

- **Decentralized peer discovery**: WireHub peers form a authentified [Kademilia
  DHT][kademilia] network, which is the by-default discovery mechanism to find
  new peers. [Sybil attack][sybil] is mitigated with a configurable
  Proof-of-Work parameter (see `workbits`);

- **Peer-to-peer and relayed communication**: WireHub goes through NATs, using
  [UPnP IGD][igd] to map new ports on compatible routers, or using [UDP Hole
  Punching][udp-hole-punching] techniques. If a P2P communication cannot be
  established, network traffic is relayed through the DHT.

## Getting started

### Quickstart with Docker

Run a minimal environment with WireHub installed.

```bash
docker run -it --cap-add NET_ADMIN wirehub/wh /bin/sh
```

Run a testing environment with auto-completion enabled, testing scripts and
debug tools installed, ...

```bash
docker run -it --cap-add NET_ADMIN wirehub/sandbox /bin/bash
```

If you want to compile the Docker images from source,

```bash
git clone --recursive https://github.com/gawen/wirehub
cd wirehub
make docker docker-sandbox
```

### A simple network with two nodes

First, generate two keys, one for each node.

```bash
$ wh genkey | tee node_a.sk | wh pubkey | tee node_a.k
zW-1lBeQ7IkT6NW6hL_NsV4eOPOwJi_rt1vO-omOEmQ
$ wh genkey | tee node_b.sk | wh pubkey | tee node_b.k
g878Bf9ZDc4IzFSUhWFTO1VYFVmHD5XfvEsVn83Dsho
```

The private keys are stored in the `.sk` files. The public keys are stored in
the `.k` files.

Generate a WireHub configuration

```bash
echo "name tutorial
subnet 10.0.42.0/24

boot P17zMwXJFbBdJEn05RFIMADw9TX5_m2xgf31OgNKX3w bootstrap.wirehub.io
trust node_a `cat node_a.k`
trust node_b `cat node_b.k`" > config
```

File `config` should be like this:

```
name tutorial           # name of network
subnet 10.0.42.0/24     # private subnetwork

# one DHT bootstrap node
boot P17zMwXJFbBdJEn05RFIMADw9TX5_m2xgf31OgNKX3w bootstrap.wirehub.io

# two nodes, node_a & node_b
trust node_a zW-1lBeQ7IkT6NW6hL_NsV4eOPOwJi_rt1vO-omOEmQ
trust node_b g878Bf9ZDc4IzFSUhWFTO1VYFVmHD5XfvEsVn83Dsho
```

To start the network, run on `node_a` ...

```bash
wh up ./config private-key ./node_a.sk
```

... and on `node_b` ...

```bash
wh up ./config private-key ./node_b.sk
```

After some time, each node should be able to ping themselves.

```
# ping node_b
PING 10.0.42.3 (10.0.42.3): 56 data bytes
64 bytes from 10.0.42.2: seq=0 ttl=64 time=106.801 ms
64 bytes from 10.0.42.2: seq=1 ttl=64 time=49.778 ms

```

You can check the overlay network status

```
# wh
interface wh-zW-1lBeQ7, network tutorial, node node_a <NAT>
  public key: zW-1lBeQ7IkT6NW6hL_NsV4eOPOwJi_rt1vO-omOEmQ

  peers
     node_b

```

While the daemon is running, you can modify the network configuration and reload
it.

```
# echo "trust node_c 9OtorxsAqPqZkJ-fAYNRAPr9piMWKMLnGqOVVpMUvXY" >> ./config
# wh reload wh-zW-1lBeQ7
```

You may stop the WireHub node as so:

```bash
wh down wh-zW-1lBeQ7
```

Advise: use auto-completion to avoid writing wirehub interface, peer's keys or
other arguments. For example,

```
# wh do<TAB>
  wh down <TAB>
  wh down wh-zW-1lBeQ7
```

### A use-case with WireHub: zero-netcat

[![demo](https://asciinema.org/a/217931.svg)](https://asciinema.org/a/217931?autoplay=1)

Zero Netcat, or `0nc`, is a modified version of [Netcat][netcat] which runs over
WireHub. It has the nice property to be secure, peer-to-peer and agnostic of the
network topology.

On one node, run the WireHub sandbox.

```
$ docker run -it --cap-add NET_ADMIN wirehub/sandbox /bin/bash
```

Run `0nc`.

```
node_a # 0nc.lua
znc invitation: ncuJonSJOS1DlFtb3HdgDJczPilrs0oPR9pwRpa_7WXwO0z-xioe_g9cdcMZkpV2b5lN7j3eLILjplBffvjdcw
```

Copy the znc invitation. Run another WireHub sandbox, call `0nc` with the
invitation as argument.

```
node_b # 0nc.lua ncuJonSJOS1DlFtb3HdgDJczPilrs0oPR9pwRpa_7WXwO0z-xioe_g9cdcMZkpV2b5lN7j3eLILjplBffvjdcw
```

`STDIN` of `node_a` is now pipe-d into `STDOUT` of `node_b`, and vice-versa.

### Start a public node

The minimal configuration for a node is something like this,

```
name public
workbit 8
boot P17zMwXJFbBdJEn05RFIMADw9TX5_m2xgf31OgNKX3w bootstrap.wirehub.io
```

Only a bootstrap node is listed, but no trusted nodes. A node with this
configuration will join the WireHub DHT and only provide support for discovery
peers and relaying data (which is a good thing for the DHT's health).

Start a public node,

```bash
curl https://raw.githubusercontent.com/gawen/wirehub/master/config/public > ./config
wh up ./config
```

Check the neighbour peers in the DHT,

```
# wh show wh-gOVQwCSUxK all
interface wh-gOVQwCSUxK, network public, node <>
  public key: gOVQwCSUxKUhUrkUSF0aDvssDfWVrrnm47ZMp5GJtDg

  peers
  ◒  BB_O_4Qxzw: 1.2.3.4:55329 (bucket:1)
  ◒  C4mfi1ltU9: 1.2.3.4:46276 (bucket:1)
  ◒  Dng_TaMHei: 1.2.3.4:6465 (bucket:1)
  ◒  GjIX1RdmDj: 1.2.3.4:53850 (bucket:1)
  ◒  G9qk6znNL5: 1.2.3.4:4523 (bucket:1)
  ◒  J_RXehMJiw: 1.2.3.4:13962 (bucket:1)
  ◒  PgjYqFfsyS: 1.2.3.4:39582 (bucket:1)
  ●  P17zMwXJFb: 51.15.227.165:62096 (bucket:1)
  [...]
```

## Dependencies

- [Libpcap][libpcap]
- [Libsodium][libsodium]
- [Lua][lua]
- [miniupnpc][miniupnpc]
- [WireGuard][wireguard]
- optionally, [Docker][docker]

## Requirements

- Linux or Docker
- WireGuard

## Current limitations

- **Untrusted cryptography**: even if WireHub basics cryptographic routines are
  based on the trusted [Libsodium][libsodium], the WireHub cryptographic
  architecture has not been audited yet. If you're interested to contribute on
  this part, help is very welcome!

- **Automatic testing**: a lot of work needs to be done to make real automatic
  testing possible with WireHub. Current efforts are on branch
  [`dev-testbed`](https://github.com/Gawen/WireHub/tree/develop-testbed) and
  [`micronet`][micronet].

- **Still panic**: still quite rough to use. Do not expect the daemon to be stable;

- **Poor documentation**: WireHub was a side project and still lacks
  documentation.

- **For a relayed peer, only one relay is used**: the traffic is not distributed
  yet between several relays, which makes a single point of failure of WireHub
  relay mechanisms;

- **Only IPv4 private addresses**: implemeting IPv6 private addresses requires
  some additional work;

- and related to WireGuard, which is still under active development.

## Future

- **Zero-configuration IP6 networking** with IPv6 [ORCHID][orchid] addresses, to
  automatically allocate each peer a default private IP (see `wh orchid`);

## Overall source code architecture

WireHub's source code is stored in `src/`. `wh.lua` is the main Lua module to
import WireHub's engine.

The source code of the CLI tool `wh` is stored in `src/tools/`. Its entry point is `src/tools/cli.lua`.

The core of WireHub is written in C and stored in `src/core/`. It is a native
Lua module called `whcore`, defined in `src/core/whcorelib.c`.

Please refer to the documentation in each files for more info.

[curve25519]: https://cr.yp.to/ecdh.html
[docker]: https://www.docker.com/
[igd]: https://en.wikipedia.org/wiki/Internet_Gateway_Device_Protocol
[kademilia]: https://en.wikipedia.org/wiki/Kademlia
[libpcap]: https://www.tcpdump.org/
[libsodium]: https://download.libsodium.org/doc/
[lua]: https://www.lua.org/
[micronet]: https://github.com/Gawen/WireHub/tree/develop-testbed/contrib/micronet
[miniupnpc]: http://miniupnp.free.fr/
[netcat]: https://en.wikipedia.org/wiki/Netcat
[orchid]: https://datatracker.ietf.org/doc/rfc4843/
[pow]: https://en.wikipedia.org/wiki/Proof-of-work_system
[sybil]: https://en.wikipedia.org/wiki/Sybil_attack
[udp-hole-punching]: https://en.wikipedia.org/wiki/UDP_hole_punching
[wireguard]: https://www.wireguard.com/
