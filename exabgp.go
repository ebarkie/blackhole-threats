// Copyright (c) 2021 Eric Barkie. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/ebarkie/netaggr/pkg/netcalc"
)

// recvMsgs consumes messages sent in response to commands.  For now this
// simply logs negative acknowledgements.
func recvMsgs() error {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		msg := scanner.Text()
		if msg == "" || msg == "done" {
			continue
		}
		log.Printf("Received message: %q", msg)
	}

	return scanner.Err()
}

func parseFeed(nets *netcalc.Nets, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = nets.ReadFrom(resp.Body)
	return err
}

type routeCmd uint8

const (
	announce routeCmd = iota
	withdraw
)

func (c routeCmd) String() string {
	switch c {
	case announce:
		return "announce"
	case withdraw:
		return "withdraw"
	default:
		return ""
	}
}

type exaBGP struct {
	asn     uint
	nextHop string
}

func (e exaBGP) route(cmd routeCmd, net ...*net.IPNet) {
	for _, n := range net {
		fmt.Printf("%s route %s next-hop %s community [%d:666]\n",
			cmd, n, e.nextHop, e.asn)
	}
}

func (e exaBGP) updateRoutes(ctx context.Context, refreshRate time.Duration, feeds []string) error {
	var prev, cur netcalc.Nets

	t := time.NewTimer(0) // Start immediately
	for {
		select {
		case <-t.C:
			log.Printf("Refresh(%s) started", refreshRate)

			prev = cur
			cur = netcalc.Nets{}
			total := 0
			for _, f := range feeds {
				parseFeed(&cur, f)
				log.Printf("Parsed %q: %d networks (%d total)", f, len(cur)-total, len(cur))
				total = len(cur)
			}

			sort.Sort(cur)
			cur.Assim()
			cur.Aggr()

			a, w := netcalc.Diff(prev, cur)
			e.route(announce, a...)
			e.route(withdraw, w...)

			t.Reset(refreshRate)
			log.Printf("%d summarized networks (%d announced/%d withdrawn)",
				len(cur), len(a), len(w))
		case <-ctx.Done():
			return nil
		}
	}
}
