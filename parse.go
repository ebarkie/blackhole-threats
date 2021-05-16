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
	// Parse all of the feeds concurrently.
	netC := make(chan *net.IPNet)
	var wg sync.WaitGroup
	wg.Add(len(feeds))
	go func() {
		wg.Wait()
		close(netC)
	}()

	for _, f := range feeds {
		go func(feed string) {
			defer wg.Done()

			r, err := readFeed(feed)
			if err != nil {
				log.WithFields(log.Fields{
					"err": err,
				}).Error("Feed read error")
				return
			}
			defer r.Close()

			i, err := netcalc.ReadFrom(r, netC)
			log.WithFields(log.Fields{
				"feed":     feed,
				"networks": i,
				"err":      err,
			}).Info("Feed parsed")

		}(f)
	}

	for n := range netC {
		nets = append(nets, n)
	}

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
