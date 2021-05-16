// Copyright (c) 2021 Eric Barkie. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package main

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"sync"

	"github.com/ebarkie/netaggr/pkg/netcalc"

	log "github.com/sirupsen/logrus"
)

// readFeed determines a feed's scheme and creates an appropriate io.ReadCloser.
func readFeed(feed string) (io.ReadCloser, error) {
	u, err := url.Parse(feed)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "http", "https":
		resp, err := http.Get(feed)
		if err != nil {
			return nil, err
		}

		return resp.Body, nil
	}

	return os.Open(feed)
}

// parseFeeds parses feeds concurrently and returns summarized nets.
func parseFeeds(feeds ...string) (nets netcalc.Nets) {
	// Read the channel and append IPNets until it's closed.
	netC := make(chan *net.IPNet)
	go func() {
		for n := range netC {
			nets = append(nets, n)
		}
	}()

	// Parse all the feeds.
	var wg sync.WaitGroup
	for _, f := range feeds {
		wg.Add(1)

		go func(feed string) {
			defer wg.Done()

			r, err := readFeed(feed)
			if err != nil {
				log.WithFields(log.Fields{
					"err": err,
				}).Error("Feed Couldn't be read")
				return
			}

			i, err := netcalc.ReadFrom(r, netC)
			log.WithFields(log.Fields{
				"feed":     feed,
				"networks": i,
				"err":      err,
			}).Info("Feed parsed")

		}(f)
	}
	wg.Wait()
	close(netC)

	// Summarize the networks.
	totalNets := len(nets)
	sort.Sort(nets)
	nets.Assim()
	nets.Aggr()
	log.WithFields(log.Fields{
		"summarized": len(nets),
		"total":      totalNets,
	}).Info("Feed parsing complete")

	return
}
