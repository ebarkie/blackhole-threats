// Copyright (c) 2021 Eric Barkie. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package main

import (
	"context"
	"net"
	"os"
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/anypb"
	"github.com/golang/protobuf/ptypes/any"
	api "github.com/osrg/gobgp/v3/api"
	gobgpconfig "github.com/osrg/gobgp/v3/pkg/config"
	"github.com/osrg/gobgp/v3/pkg/config/oc"
	"github.com/osrg/gobgp/v3/pkg/server"
	log "github.com/sirupsen/logrus"
)

// NewServer creates, starts, and configures a new BGP server with configFile.
func NewServer(config *oc.BgpConfigSet) (Blackhole, error) {
	s := server.NewBgpServer()
	go s.Serve()
	_, err := gobgpconfig.InitialConfig(context.Background(), s, config, true)

	return Blackhole{
		server:   s,
		as:       config.Global.Config.As,
		routerID: config.Global.Config.RouterId,
	}, err
}

// Blackhole is a BGP threat black hole route server.
type Blackhole struct {
	// GoBGP BGP server.
	server *server.BgpServer

	// Local Autonomous System number of the router.  Uses
	// the 32-bit AS-number type from the model in RFC 6991.
	as uint32

	// ID of the router expressed as an IPv4 address.
	routerID string

	// List of IPv4/6 threat feed URL's to download.
	Feeds []FeedConfig

	// Feeds refresh timer.
	RefreshRate time.Duration

	// Signal channel used to trigger an immediate refresh of feeds.
	SigC chan os.Signal
}

func (bh Blackhole) announce(ipnet *net.IPNet, comms ...uint32) error {
	return bh.addPath(ipnet, comms...)
}

func (bh Blackhole) withdraw(ipnet *net.IPNet) error {
	return bh.addPath(ipnet)
}

// addPath announces a network with the specified communities, or withdraws it
// if there are no communities.
func (bh Blackhole) addPath(ipnet *net.IPNet, comms ...uint32) error {
	var (
		v4Family = &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}
		v6Family = &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}
	)

	ones, bits := ipnet.Mask.Size()

	nlri, err := anypb.New(&api.IPAddressPrefix{
		Prefix:    ipnet.IP.String(),
		PrefixLen: uint32(ones),
	})
	if err != nil {
		return err
	}

	originAttr, _ := anypb.New(&api.OriginAttribute{
		Origin: 0,
	})

	communitiesAttr, _ := anypb.New(&api.CommunitiesAttribute{
		Communities: comms,
	})

	var family *api.Family
	var nextHopAttr *anypb.Any
	if bits <= 32 { // IPv4
		family = v4Family
		nextHopAttr, _ = anypb.New(&api.NextHopAttribute{
			NextHop: bh.routerID,
		})
	} else { // IPv6
		family = v6Family
		nextHopAttr, _ = anypb.New(&api.MpReachNLRIAttribute{
			Family:   v6Family,
			Nlris:    []*any.Any{nlri},
			NextHops: []string{"::ffff:" + bh.routerID},
		})
	}

	var isWithdraw bool
	if len(comms) < 1 {
		isWithdraw = true
	}

	_, err = bh.server.AddPath(context.Background(), &api.AddPathRequest{
		Path: &api.Path{
			Family:     family,
			Nlri:       nlri,
			Pattrs:     []*any.Any{originAttr, nextHopAttr, communitiesAttr},
			IsWithdraw: isWithdraw,
		}})

	return err
}

type bgpNets map[string][]Comm

func (b *bgpNets) add(ipnet *net.IPNet, comm Comm) {
	cidr := ipnet.String()
	(*b)[cidr] = append((*b)[cidr], comm)
}

func (b *bgpNets) reset() {
	*b = make(bgpNets)
}

func diffF(a, b bgpNets, f func(*net.IPNet, ...uint32) error) (int, error) {
	var n int
	for cidr, aComms := range a {
		bComms, exists := b[cidr]
		// If there is any difference in communities then we need to
		// withdraw and re-announce the network.
		if exists && slices.Equal(aComms, bComms) {
			continue
		}

		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return n, err
		}
		comms := make([]uint32, len(aComms))
		for i := range len(aComms) {
			comms[i] = uint32(aComms[i])
		}
		if err := f(ipnet, comms...); err != nil {
			return n, err
		}
		n++
	}

	return n, nil
}

// UpdateRoutes continuously downloads the feeds and refreshes routes at the
// specified refresh rate.
func (bh Blackhole) UpdateRoutes(ctx context.Context) error {
	// Sort feeds into distinct communities for parsing and summarizing
	commFeeds := make(map[Comm][]string)
	for _, c := range bh.Feeds {
		if c.Comm < 1 {
			// RFC7999 blackhole community
			c.Comm = Comm(bh.as<<16 ^ 666)
		}

		commFeeds[c.Comm] = append(commFeeds[c.Comm], c.URL)
	}
	var distinctComms []Comm
	for comm := range commFeeds {
		distinctComms = append(distinctComms, comm)
	}
	slices.Sort(distinctComms)

	var prev, cur bgpNets

	t := time.NewTimer(0) // Update immediately on startup
	for {
		select {
		case <-t.C:
			log.WithFields(log.Fields{
				"communities": len(distinctComms),
				"rate":        bh.RefreshRate,
			}).Debug("Refresh started")

			prev = cur
			cur.reset()
			for _, comm := range distinctComms {
				feeds := commFeeds[comm]
				nets, totalNets := parseFeeds(feeds...)
				log.WithFields(log.Fields{
					"community":  comm.String(),
					"feeds":      feeds,
					"summarized": len(nets),
					"total":      totalNets,
				}).Info("Parsed feeds")

				for _, net := range nets {
					cur.add(net, comm)
				}
			}

			wn, err := diffF(prev, cur, func(ipnet *net.IPNet, _ ...uint32) error {
				log.WithFields(log.Fields{
					"net": ipnet.String(),
				}).Trace("Withdrew network")
				return bh.withdraw(ipnet)

			})
			if err != nil {
				return err
			}

			an, err := diffF(cur, prev, func(ipnet *net.IPNet, comms ...uint32) error {
				log.WithFields(log.Fields{
					"communities": comms,
					"net":         ipnet.String(),
				}).Trace("Announced network")
				return bh.announce(ipnet, comms...)

			})
			if err != nil {
				return err
			}

			log.WithFields(log.Fields{
				"nets":      len(cur),
				"announced": an,
				"withdrawn": wn,
			}).Info("Refresh complete")
			t.Reset(bh.RefreshRate)
		case s := <-bh.SigC: // SIGUSR1
			log.WithFields(log.Fields{
				"sig": s,
			}).Warn("Received refresh signal")
			t.Reset(0)
		case <-ctx.Done():
			log.Warn(ctx.Err())
			return nil
		}
	}
}

// Stop shuts down the blackhole server.
func (bh Blackhole) Stop() error {
	return bh.server.StopBgp(context.Background(), &api.StopBgpRequest{})
}
