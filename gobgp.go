// Copyright (c) 2021 Eric Barkie. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package main

import (
	"context"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/ebarkie/netaggr/pkg/netcalc"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/pkg/config"
	"github.com/osrg/gobgp/pkg/server"
	log "github.com/sirupsen/logrus"
)

func parseFeed(nets *netcalc.Nets, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = nets.ReadFrom(resp.Body)
	return err
}

func NewServer(configFile string) (BlackHole, error) {
	c, err := config.ReadConfigFile(configFile, "toml")
	if err != nil {
		return BlackHole{}, err
	}

	s := server.NewBgpServer()
	go s.Serve()

	_, err = config.InitialConfig(context.Background(), s, c, true)

	return BlackHole{
		server:   s,
		as:       c.Global.Config.As,
		routerId: c.Global.Config.RouterId,
	}, err
}

type BlackHole struct {
	server   *server.BgpServer
	as       uint32
	routerId string

	RefreshRate time.Duration
	Feeds       urls
}

func (bh BlackHole) announce(nets ...*net.IPNet) error {
	return bh.addPath(false, nets...)
}

func (bh BlackHole) withdraw(nets ...*net.IPNet) error {
	return bh.addPath(true, nets...)
}

func (bh BlackHole) addPath(withdraw bool, nets ...*net.IPNet) error {
	for _, n := range nets {
		prefixLen, _ := n.Mask.Size()
		nlri, _ := ptypes.MarshalAny(&api.IPAddressPrefix{
			Prefix:    n.IP.String(),
			PrefixLen: uint32(prefixLen),
		})

		origin, _ := ptypes.MarshalAny(&api.OriginAttribute{
			Origin: 0,
		})
		nextHop, _ := ptypes.MarshalAny(&api.NextHopAttribute{
			NextHop: bh.routerId,
		})
		communities, _ := ptypes.MarshalAny(&api.CommunitiesAttribute{
			Communities: []uint32{bh.as<<16 ^ 666},
		})

		_, err := bh.server.AddPath(context.Background(), &api.AddPathRequest{
			Path: &api.Path{
				Family:     &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
				Nlri:       nlri,
				Pattrs:     []*any.Any{origin, nextHop, communities},
				IsWithdraw: withdraw,
			}})
		if err != nil {
			return err
		}
	}

	return nil
}

func (bh BlackHole) UpdateRoutes(ctx context.Context) error {
	var prev, cur netcalc.Nets

	t := time.NewTimer(0) // Update immediately on startup
	for {
		select {
		case <-t.C:
			log.WithFields(log.Fields{"rate": bh.RefreshRate}).Debug("Refresh started")

			prev = cur
			cur = netcalc.Nets{}
			total := 0
			for _, f := range bh.Feeds {
				err := parseFeed(&cur, f)
				log.WithFields(log.Fields{
					"feed":     f,
					"networks": len(cur) - total,
					"total":    len(cur),
					"err":      err,
				}).Info("Parsed feed")
				total = len(cur)
			}

			sort.Sort(cur)
			cur.Assim()
			cur.Aggr()

			a, w := netcalc.Diff(prev, cur)
			if err := bh.announce(a...); err != nil {
				return err
			}
			if err := bh.withdraw(w...); err != nil {
				return err
			}

			t.Reset(bh.RefreshRate)
			log.WithFields(log.Fields{
				"networks":  len(cur),
				"announced": len(a),
				"withdrawn": len(w),
			}).Info("Refresh complete")
		case <-ctx.Done():
			return nil
		}
	}
}
