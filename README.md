![Push](https://github.com/ebarkie/blackhole-threats/workflows/Push/badge.svg)

# Blackhole threats (with ExaBGP)

This is an [ExaBGP](https://github.com/Exa-Networks/exabgp) API process which
downloads IPv4/v6 threat feeds on a periodic basis, summarizes them, and
maintains them as routes.  Routers can then peer with ExaBGP and blackhole
these routes.

## Usage

```
Usage of ./blackhole-threats:
  -asn string
    	Autonomous System Number between 64512-65534 (default "64512")
  -feed value
    	Threat intelligence feed (use multiple times)
  -nexthop string
    	Next hop for routes (default "192.168.0.254")
  -refresh-rate duration
    	Refresh timer (default 1h0m0s)
```

## Configuration

### ExaBGP v4

```
process threats {
	run /etc/exabgp/exabgp-blackhole -feed https://www.spamhaus.org/drop/drop.txt -feed https://www.spamhaus.org/drop/edrop.txt -feed https://www.talosintelligence.com/documents/ip-blacklist -feed https://sslbl.abuse.ch/blacklist/sslipblacklist.txt -feed https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt -feed https://lists.blocklist.de/lists/all.txt;
	encoder text;
}

template {
	neighbor firewall {
		family {
			ipv4 unicast;
			ipv6 unicast;
		}

		api connection {
			processes [ threats ];
		}
	}
}

neighbor 192.168.1.1 {
	inherit firewall;

	local-as 64512;
	peer-as 64512;
	local-address 192.168.1.2;
	router-id 192.168.1.2;
}
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
