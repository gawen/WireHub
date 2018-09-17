# micronet

`micronet` is a small software to simulate IP networks. A network topology is
defined in a configuration file. A server is run and relay the traffic between
the peers. Each peer runs a client which initiate a TUN IP tunnel on which all IP
traffic is routed.

It is used to test WireHub in a simulated Internet on one single machine.
Containers are spawned with WireHub running, and micronet routes the network
traffic between containers.

Configuration files language is a DSL over Lua. For example,

```
-- Initiate a WAN
W = wan()

-- Initiate a public peer, with IP 51.15.227.165. It will act as the WireHub's
-- bootstrap node
M(W | peer{up_ip=subnet('51.15.227.165', 0)})

-- Initiate another public peer, with IP 1.1.1.1
M(W | peer{up_ip=subnet("1.1.1.1", 0)})

-- Initiate a peer behind a full-cone NAT whose IP is 1.1.1.2
M(W | nat{up_ip=subnet('1.1.1.2', 0), mode=NAT_FULL_CONE} | peer())
```

## Features

- **NATs**: symmetric, full-cone, restricted-cone and restricted-port NATs are
  supported;

- **ICMP echo and echo reply**: used for network pings;

- **UDP**: used by WireHub;

- **Extensible network componenets with Lua**: network components can be
  customized in Lua (see the NAT component).

## TODO

- TCP through NAT: TCP traffic going through NAT is currently not supported
  and no effort was done to make it work, as not required by WireHub.

- Hop simulation: Currently, TTL of IP packets are not decremented. A
  traceroute will report always one hop.

- UPnP support

- Simulated latency and packet drops
