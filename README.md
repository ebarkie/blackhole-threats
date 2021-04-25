![Push](https://github.com/ebarkie/blackhole-threats/workflows/Push/badge.svg)

# Blackhole threats (with GoBGP)

This is a stand-alone BGP server based on [GoBGP](https://github.com/osrg/gobgp)
which downloads IPv4/v6 threat feeds on a periodic basis, summarizes them, and
maintains them as routes.  Routers can then iBGP peer with it and blackhole
these routes.

## Usage

```
Usage of ./blackhole-threats:
  -debug
    	Enable debug logging
  -f string
    	GoBGP configuration file (default "gobgpd.conf")
  -feed value
    	Threat intelligence feed (use multiple times)
  -refresh-rate duration
    	Refresh timer (default 1h0m0s)
```

## Configuration

### GoBGP

```toml
[global.config]
  as = 64512
  router-id = "192.168.1.2"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "192.168.1.1"
    peer-as = 64512
```

### Mikrotik RouterOS

```
/routing bgp instance
set default as=64512
/routing bgp peer
add allow-as-in=2 comment="C&C and don't route or peer IP's" in-filter=threats-in name=threats \
    remote-address=192.168.1.2 ttl=default
/routing filter
add action=accept bgp-communities=64512:666 chain=threats-in comment=\
    "Blackhole C&C and don't route or peer IP's" protocol=bgp set-type=blackhole
```

## License

Copyright (c) 2021 Eric Barkie. All rights reserved.  
Use of this source code is governed by the MIT license
that can be found in the [LICENSE](LICENSE) file.
