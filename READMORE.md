# Principles

A WireHub **peer** is a network node running WireHub. Each peer has a Curve25519
private key, used as a proof of its identity in the network. Its network address
is its Curve25519 public key. The human-readable version of a peer address is
encoded with Base64 (e.g. `P17zMwXJF..._KX3w`).

Peers form a Kademilia DHT. The distance function `XOR` is used to make peers
close to each other aware of themselves. By requesting consecutively the closest
peers of one which is being looked up, peers are able to find the IPv6 or IPv6
public address of another peer decentralizedly. Central servers may be provided,
but the network keeps working if they are unreachable.

Peers can form **private networks**. A private network sets a list of
**trusted peers** which has each a private IP address and optionally a hostname.
Application's network traffic of trusted peers are sent through WireGuard
tunnels.

A private network is defined by a single configuration file, like so

```
[Network]
Name = jgl
Namespace = public
Workbits = 8
SubNetwork = 10.0.42.1/24

[Peer]
# Trust = no
Bootstrap = yes
Name = bootstrap
PublicKey = P17zMwXJFbBdJEn05RFIMADw9TX5_m2xgf31OgNKX3w
Endpoint = 123.45.67.89:62096

[Peer]
Trust = yes
Name = 1.relay
IP = 10.0.42.1
PublicKey = ZvuWjYZPQL7NGBZKXsB7zJgqVpY3zG_h-8ALBE3QHTM

[Peer]
Trust = yes
Name = 2.relay
IP = 10.0.42.2
PublicKey = vpeUTmuhSM44waVt0iquAd3E-GvjZ6kvKPHCuMymaks

...
```

WireHub try to go through NATs to establish a peer-to-peer communication. If not
possible, application's network traffic is relayed through relay peers. Trusted
relay peers SHOULD BE preferred (TODO).

## Public network

XXX Every peer keep a list of other seen (non-trusted) peers

## Advanced

### Sybil attacks

WireHub provides a Proof-of-Work mechanism to mitigate Sybil attack. Each private
network sets the field `WorkBit`. **Work bits** are the count of MSB bits set to
zero of a Blake2b hash of the Curve25519 public key. Any peer which does not
have the necessary amount of work bits will be rejected.

The bigger the work bits, the more mitigated the sybil attack is. Each added
work bit multiply by 2 the complexity of generating a new identity.

## Getting started

The CLI tool to set up WireHub is `wh`. Make sure to enable auto-completion.

