![Push](https://github.com/ebarkie/blackhole-threats/workflows/Push/badge.svg)

# Blackhole threats (with GoBGP)

Stand-alone BGP route server based on [GoBGP](https://github.com/osrg/gobgp)
which downloads IPv4/v6 threat feeds on a periodic basis, summarizes them, and
maintains them as routes.  Routers can then peer with it and
[blackhole](https://en.wikipedia.org/wiki/Black_hole_(networking)) these routes.

## Usage

```
Usage of ./blackhole-threats:
  -debug
    	Enable debug logging
  -conf string
    	Configuration file (default "blackhole-threats.yaml")
  -feed value
    	Threat intelligence feed (use multiple times)
  -refresh-rate duration
    	Refresh timer (default 2h0m0s)
```

## Feeds

Some threat intelligence feeds:
- [abuse.ch Botnet C2 IP Blacklist](https://sslbl.abuse.ch/blacklist/sslipblacklist.txt)
- [blocklist.de fail2ban reporting service](https://lists.blocklist.de/lists/all.txt)
- [Emerging Threats fwip rules](https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
- [Spamhaus Don't Route Or Peer List (DROP)](https://www.spamhaus.org/drop/drop.txt)
- [Spamhaus Extended DROP List (EDROP)](https://www.spamhaus.org/drop/edrop.txt)
- [Talos IP Blacklist](https://www.talosintelligence.com/documents/ip-blacklist)

## Configuration

```yaml
gobgp:
  global:
    config:
      as: 64512
      routerid: "192.168.1.1"
  neighbors:
    - config:
        neighboraddress: "192.168.1.1"
        peeras: 64512

# Each feed consists of a URL and optional community.
#
# The community is defined as "<as>:<action>" and each part may be in
# the range of 0-65535.  If a community is not defined then it will default
# to "<global as>:666".
feeds:
#  - url: http://localhost/drop.txt
#    community: 64512:666
```

### Mikrotik RouterOS

#### v6

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

#### v7

```
/routing bgp template
set default as=64512 disabled=no routing-table=main
/routing bgp connection
add address-families=ip,ipv6 as=64512 disabled=no input.allow-as=2 .filter=threats-in local.role=ibgp \
    name=threats remote.address=192.168.1.2 routing-table=main templates=default
/routing filter rule
add chain=threats-in comment="Blackhole C&C and don't route or peer addresses" disabled=no rule=\
    "if (bgp-communities equal 64512:666) {set blackhole yes; accept}"
```

## License

Copyright (c) 2021 Eric Barkie. All rights reserved.  
Use of this source code is governed by the MIT license
that can be found in the [LICENSE](LICENSE) file.
