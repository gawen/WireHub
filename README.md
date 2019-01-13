# WireHub

WireHub (in a shell, *wh*) is a simple, small, peer-to-peer, decentralized,
extensible VPN. It uses [WireGuard tunnels][wireguard] and provides distributed
peer discovery & routing capabilities, NAT trasversal, extendable name
resolving, ...

It is written in C and Lua and is <10KLOC.

⚠️ **Not ready for production!** This is still a work-in-progress. It still
requires some work to be clean and secure. The current code is provided for
testing only.

## Features

- **Easy management of networks**: a network is defined by a single configuration
  file which lists trusted peers.

- **Cryptographic network addresses**: the network address of a peer is - or
  derived from - a [Curve25519][curve25519] public key.

- **Decentralized discovery**: WireHub peers form a [Kademilia
  DHT][kademilia] network which is the by-default
  discovery mechanism to find new peers. [Sybil attack][sybil] is mitigated with
  a configurable Proof-of-Work parameter;

- **Peer-to-Peer communication**: WireHub goes through NATs, using [UPnP
  IGD][igd] to map new ports on compatible routers, or using [UDP Hole
  Punching][udp-hole-punching] techniques.

- **Relay communication**: if a peer-to-peer communication cannot be established, network
  traffic is relayed through trusted relayed servers, or at the very least peers
  from the community of WireHub nodes.

## Getting started

### Start a public peer

[![demo](https://asciinema.org/a/217919.svg)](https://asciinema.org/a/217919?autoplay=1)

Clone the current repository.

```
$ git clone --recursive https://github.com/Gawen/WireHub
$ cd WireHub
```

Build the Docker images [`wirehub/wh`][wh-docker] and [`wirehub/sandbox`][sandbox-docker].
 The former is a minimalist Docker image with WireHub. The latter is handier to
 use (auto-completion enabled, debug tooling installed, testing scripts present,
 ...).

```
$ make docker docker-sandbox
```

Start a WireHub's sandbox,

```
$ docker run -it --cap-add NET_ADMIN wirehub/sandbox /bin/bash
```

Make sure WireHub is installed.

```
# wh help
Usage: wh <cmd> [<args>]

[...]
```

Set up the minimal configuration for the `public` network.

```
# curl https://raw.githubusercontent.com/Gawen/WireHub/master/config/public | wh setconf public -
# wh showconf public
[Network]
Name = public
Namespace = public
Workbits = 8

[Peer]
# Trust = no
Bootstrap = yes
PublicKey = P17zMwXJFbBdJEn05RFIMADw9TX5_m2xgf31OgNKX3w
Endpoint = 51.15.227.165:62096
```
Starts a peer for network `public`.

```
# wh up public
```

You can make sure WireHub is running.

```
# wh
interface gOVQwCSUxK, network public, node <>
  public key: gOVQwCSUxKUhUrkUSF0aDvssDfWVrrnm47ZMp5GJtDg
```

No peers are displayed, as no trusted peers were set up.

Here to see all peers (non-trusted included).

```
# wh show gOVQwCSUxK all
interface gOVQwCSUxK, network public, node <>
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

Advise: use auto-completion to avoid writing wirehub interface, peer's keys or
other arguments. For example, one could write:

```
# wh sh<TAB>
  wh show <TAB>
  wh show gOVQwCSUxK a<TAB>
  wh show gOVQwCSUxK all
```

We now have a WireHub peer, but without any trusted peers. No WireGuard tunnel
was instantiated yet. Your node is part of the public Kademilia DHT, and will
contribute to peer decentralized discovery and traffic relaying.

You may stop the WireHub peer as so:

```
# wh down gOVQwCSUxK
```

### Create a simple private network

[![demo](https://asciinema.org/a/217920.svg)](https://asciinema.org/a/217920?autoplay=1)

Let's create a private network called `tutorial`, with two peers: `node_a` and
`node_b`.

Start a sandbox on `node_a` and `node_b`. Run on both nodes:

```
$ docker run -it --cap-add NET_ADMIN wirehub/sandbox /bin/bash
```

First, make sure [WireGuard][wireguard] is installed.

```
$ wh check-wg
OK! WireGuard is installed.
```

Peers of the private network `tutorial` will bootstrap through the `public`
network. To do so, copy the network `public` in the network `tutorial`. Run on
both nodes:

```
# wh showconf public | wh setconf tutorial -
```

Set the private network IP subnetwork to `10.0.42.0/24` (for example). Run on
both nodes:

```
# wh set tutorial subnet 10.0.42.0/24
```

Generate private and public keys.

```
node_a # wh genkey tutorial | tee node_a.sk | wh pubkey | tee node_a.k
zW-1lBeQ7IkT6NW6hL_NsV4eOPOwJi_rt1vO-omOEmQ
...
node_b # wh genkey tutorial | tee node_b.sk | wh pubkey | tee node_b.k
g878Bf9ZDc4IzFSUhWFTO1VYFVmHD5XfvEsVn83Dsho
```

Set up the private `tutorial` with the trusted peers `node_a` and `node_b`:
`node_a` will have private IP address `10.0.42.1` and `node_b` `10.0.42.2`. Run
on both nodes:

```
# wh set tutorial ip 10.0.42.1 name node_a peer zW-1lBeQ7IkT6NW6hL_NsV4eOPOwJi_rt1vO-omOEmQ
# wh set tutorial ip 10.0.42.2 name node_b peer g878Bf9ZDc4IzFSUhWFTO1VYFVmHD5XfvEsVn83Dsho
```

You can check the current configuration of network `tutorial`:

```
# wh showconf tutorial
[Network]
Name = tutorial
Namespace = public
Workbits = 8
SubNetwork = 10.0.42.0/24

[Peer]
# Trust = no
Bootstrap = yes
PublicKey = P17zMwXJFbBdJEn05RFIMADw9TX5_m2xgf31OgNKX3w
Endpoint = 51.15.227.165:62096

[Peer]
Trust = yes
Name = node_a
IP = 10.0.42.1
PublicKey = zW-1lBeQ7IkT6NW6hL_NsV4eOPOwJi_rt1vO-omOEmQ

[Peer]
Trust = yes
Name = node_b
IP = 10.0.42.2
PublicKey = g878Bf9ZDc4IzFSUhWFTO1VYFVmHD5XfvEsVn83Dsho
```

Create a WireGuard tunnel for the network `tutorial`:

```
node_a # ip link add dev wg-tutorial type wireguard
node_a # wg set wg-tutorial private-key ./node_a.sk listen-port 0
node_a # ip link set wg-tutorial up
...
node_b # ip link add dev wg-tutorial type wireguard
node_b # wg set wg-tutorial private-key ./node_b.sk listen-port 0
node_b # ip link set wg-tutorial up
```

Start the private network. Run on both nodes:

```
# wh up tutorial interface wg-tutorial
```

You can check the status of the VPN:

```
node_a # wh
interface wg-tutorial, network tutorial, node node_a <NAT>
  public key: zW-1lBeQ7IkT6NW6hL_NsV4eOPOwJi_rt1vO-omOEmQ

  peers
     node_b
...
node_b # wh
interface wg-tutorial, network tutorial, node node_b <NAT>
  public key: g878Bf9ZDc4IzFSUhWFTO1VYFVmHD5XfvEsVn83Dsho

  peers
     node_a
```

Now ping `node_b` from `node_a`:

```
peer_a # ping 10.0.42.2
PING 10.0.42.2 (10.0.42.2): 56 data bytes
64 bytes from 10.0.42.2: seq=0 ttl=64 time=106.801 ms
64 bytes from 10.0.42.2: seq=1 ttl=64 time=49.778 ms
...
```

### Zero Netcat

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

- **Still panic**: still quite rough to use. Do not expect the daemon to be stable;

- **Untrusted cryptography**: even if WireHub basics cryptographic routines are
  based on the trusted [Libsodium][libsodium], the WireHub cryptographic
  architecture has not been audited yet. If you're interested to contribute on
  this part, help is very welcome!

- **Automatic testing**: a lot of work needs to be done to make real automatic
  testing possible with WireHub. Current efforts are on branch
  [`dev-testbed`](https://github.com/Gawen/WireHub/tree/develop-testbed) and
  [`micronet`][micronet].

- **Poor documentation**: WireHub was a personal project and lacks
  documentation. While this will be progressively solved in the future, in the
  meantime, feel free to get in touch if you have any question regarding the
  internals.

- **For a relayed peer, only one relay is used**: the traffic is not distributed
  yet between several relays, which makes a single point of failure of WireHub
  relay mechanisms;

- **Only IPv4 private addresses**: implemeting IPv6 private addresses requires
  some additional work;

- and related to WireGuard, which is still under active development.

## Future

- **GNU Name Service Switch plug-in** to allow name resolution of WireHub peers
  by common Linux programs (see `wh resolve`).

- **Zero-configuration networking** with IPv6 [ORCHID][orchid] addresses: every
  peer has an allocated IP address (see `wh orchid`);

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
[sandbox-docker]: https://hub.docker.com/r/wirehub/sandbox/
[sybil]: https://en.wikipedia.org/wiki/Sybil_attack
[udp-hole-punching]: https://en.wikipedia.org/wiki/UDP_hole_punching
[wh-docker]: https://hub.docker.com/r/wirehub/wh/
[wireguard]: https://www.wireguard.com/
