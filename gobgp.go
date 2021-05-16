// Copyright (c) 2021 Eric Barkie. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package main

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/ebarkie/netaggr/pkg/netcalc"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/pkg/config"
	"github.com/osrg/gobgp/pkg/server"
	log "github.com/sirupsen/logrus"
)

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

	Feeds       urls
	RefreshRate time.Duration
	SigC        chan os.Signal
}

func (bh BlackHole) announce(nets ...*net.IPNet) error {
	return bh.addPath(false, nets...)
}

func (bh BlackHole) withdraw(nets ...*net.IPNet) error {
	return bh.addPath(true, nets...)
}

func (bh BlackHole) addPath(withdraw bool, nets ...*net.IPNet) error {
	var (
		v4Family = &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}
		v6Family = &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}
	)

	for _, n := range nets {
		ones, bits := n.Mask.Size()

		nlri, err := ptypes.MarshalAny(&api.IPAddressPrefix{
			Prefix:    n.IP.String(),
			PrefixLen: uint32(ones),
		})
		if err != nil {
			return err
		}

		origin, _ := ptypes.MarshalAny(&api.OriginAttribute{
			Origin: 0,
		})
		communities, _ := ptypes.MarshalAny(&api.CommunitiesAttribute{
			Communities: []uint32{bh.as<<16 ^ 666}, // RFC7999
		})

		var family *api.Family
		var nextHop *anypb.Any
		if bits <= 32 { // IPv4
			family = v4Family
			nextHop, _ = ptypes.MarshalAny(&api.NextHopAttribute{
				NextHop: bh.routerId,
			})
		} else { // IPv6
			family = v6Family
			nextHop, _ = ptypes.MarshalAny(&api.MpReachNLRIAttribute{
				Family:   v6Family,
				Nlris:    []*any.Any{nlri},
				NextHops: []string{"::ffff:" + bh.routerId},
			})
		}

		_, err = bh.server.AddPath(context.Background(), &api.AddPathRequest{
			Path: &api.Path{
				Family:     family,
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
			log.WithFields(log.Fields{
				"rate": bh.RefreshRate,
			}).Debug("Refresh started")

			prev = cur
			cur = parseFeeds(bh.Feeds...)

			a, w := netcalc.Diff(prev, cur)
			if err := bh.announce(a...); err != nil {
				return err
			}
			if err := bh.withdraw(w...); err != nil {
				return err
			}

			t.Reset(bh.RefreshRate)
			log.WithFields(log.Fields{
				"nets":      len(cur),
				"announced": len(a),
				"withdrawn": len(w),
			}).Info("Refresh complete")
		case s := <-bh.SigC:
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

func (bh BlackHole) Stop() error {
	return bh.server.StopBgp(context.Background(), &api.StopBgpRequest{})
}
