# WireHub

WireHub (in a shell, *wh*) is a simple, small, peer-to-peer, decentralized,
extensible VPN. It goes through NATs. It uses [WireGuard tunnels][wireguard] and
provides distributed peer discovery & routing capabilities, NAT trasversal,
extendable name resolving, ...

It is written in C and Lua and is <10KLOC.

⚠️ **Not ready for production!** This is still a work-in-progress. It still
requires some work to be clean and secure. The current code is provided for
testing only.

## Features

- **Easy management of networks**: a network is defined by a single configuration
  file which lists trusted peers.

- **Decentralized discovery**: WireHub peers form a [Kademilia
  DHT][kademilia] network which is the by-default
  discovery mechanism to find new peers. [Sybil attack][sybil] is mitigated with
  a configurable Proof-of-Work parameter;

- **Peer-to-Peer communication**: WireHub go through NATs using ([UPnP
  IGD][igd]) to map new ports on compatible routers, or using [UDP Hole
  Punching][udp-hole-punching].

- **Relay communication**: if a P2P communication cannot be established, network
  traffic is relayed through trusted relayed servers, or at the very least peers
  from the community of WireHub nodes.

## Dependencies

- [Libpcap][libpcap]
- [Libsodium][libsodium]
- [Lua][lua]
- [WireGuard][wireguard]
- optionally, [Docker][docker]

## Requirements

- Linux or Docker
- WireGuard

## Quickstart with Docker

You can test WireHub with Docker with the image [`wirehub/wh`][wh-docker].
There's a playground container [`wirehub/sandbox`][sandbox-docker] which is
handier to use (auto-completion enabled, debug tooling, live troubleshooting
ready, ...).

To build the Docker images manually,

```
$ git clone https://github.com/Gawen/WireHub
$ cd WireHub
$ git submodule update --init
$ make docker-sandbox
```

Start a sandbox,

```
$ docker run -it wirehub/sandbox --cap-add NET_ADMIN wirehub /bin/bash
```

Make sure WireHub is installed.

```
$ wh help
Usage: wh <cmd> [<args>]

[...]
```

Set up the minimal configuration for the `public` network.

```
$ curl https://gawenr.keybase.pub/wirehub/bootstrap-unstable | wh setconf public
```

An example configuration for the network `public` looks like this:

```
# Example configuration for WireHub public network

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
$ wh up public
```

You can make sure WireHub is running.

```
$ wh
interface gOVQwCSUxK, network public, node <>
  public key: gOVQwCSUxKUhUrkUSF0aDvssDfWVrrnm47ZMp5GJtDg
```

Here to see all peers.

```
$ wh show gOVQwCSUxK all
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

### Current limitations

- **Untrusted cryptography**: even if WireHub basics cryptographic routines are
  based on the trusted [Libsodium][libsodium], the WireHub cryptographic
  architecture has not been audited yet. If you're interested to contribute on
  this part, help is very welcome!

- **Still panic**: still quite rough to use. Do not expect the daemon to be stable;

- **For a relayed peer, only one relay is used**: the traffic is not distributed
  yet between several relays, which makes a single point of failure of WireHub
  relay mechanisms;

- **Only IPv4**: implemeting IPv6 requires some additional work;

- and related to WireGuard, which is still under active development.

### Future

- **Zero-configuration networking with IPv6 [ORCHID][orchid] addresses**: every
  peer has an allocated IP address (see `wh orchid`);

[docker]: https://www.docker.com/
[igd]: https://en.wikipedia.org/wiki/Internet_Gateway_Device_Protocol
[kademilia]: https://en.wikipedia.org/wiki/Kademlia
[libpcap]: https://www.tcpdump.org/
[libsodium]: https://download.libsodium.org/doc/
[lua]: https://www.lua.org/
[orchid]: https://datatracker.ietf.org/doc/rfc4843/
[pow]: https://en.wikipedia.org/wiki/Proof-of-work_system
[sandbox-docker]: https://hub.docker.com/r/wirehub/sandbox/
[sybil]: https://en.wikipedia.org/wiki/Sybil_attack
[udp-hole-punching]: https://en.wikipedia.org/wiki/UDP_hole_punching
[wh-docker]: https://hub.docker.com/r/wirehub/wh/
[wireguard]: https://www.wireguard.com/
