![Push](https://github.com/ebarkie/blackhole-threats/workflows/Push/badge.svg)

# Blackhole threats (with GoBGP)

This is a stand-alone BGP route server based on [GoBGP](https://github.com/osrg/gobgp)
which downloads IPv4/v6 threat feeds on a periodic basis, summarizes them, and
maintains them as routes.  Routers can then iBGP peer with it and blackhole
these routes.

## Usage

```
Usage of ./blackhole-threats:
  -debug
    	Enable debug logging
  -conf string
    	GoBGP configuration file (default "gobgpd.conf")
  -feed value
    	Threat intelligence feed (use multiple times)
  -refresh-rate duration
    	Refresh timer (default 1h0m0s)
```

## Feeds

Some interesting threat intelligence feeds:
- [abuse.ch Botnet C2 IP Blacklist](https://sslbl.abuse.ch/blacklist/sslipblacklist.txt)
- [blocklist.de fail2ban reporting service](https://lists.blocklist.de/lists/all.txt)
- [Emerging Threats fwip rules](https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
- [Spamhaus Don't Route Or Peer List (DROP)](https://www.spamhaus.org/drop/drop.txt)
- [Spamhaus Extended DROP List (EDROP)](https://www.spamhaus.org/drop/edrop.txt)
- [Talos IP Blacklist](https://www.talosintelligence.com/documents/ip-blacklist)

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
add address-families=ip,ipv6 allow-as-in=2 in-filter=threats-in name=threats remote-address=\
    192.168.1.2 ttl=default
/routing filter
add action=accept address-family=ip bgp-communities=64512:666 chain=threats-in comment=\
    "Blackhole IPv4 C&C and don't route or peer addresses" protocol=bgp set-type=blackhole
add address-family=ipv6 bgp-communities=64512:666 chain=threats-in comment=\
    "Unreachable IPv6 C&C and don't route or peer addresses" protocol=bgp set-type=unreachable
```

## License

Copyright (c) 2021 Eric Barkie. All rights reserved.  
Use of this source code is governed by the MIT license
that can be found in the [LICENSE](LICENSE) file.
