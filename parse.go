// Copyright (c) 2021 Eric Barkie. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/ebarkie/netaggr/pkg/netcalc"

	log "github.com/sirupsen/logrus"
)

var ErrUnhandledScheme = errors.New("unhandled scheme")

// readFeed reads a feed and returns the number of networks.
func readFeed(feed string, netC chan<- *net.IPNet) (int64, error) {
	u, err := url.Parse(feed)
	if err != nil {
		return 0, err
	}

	switch u.Scheme {
	case "":
		r, err := os.Open(feed)
		if err != nil {
			return 0, err
		}
		defer r.Close()

		if strings.HasSuffix(feed, ".json") {
			return readFromJSON(r, netC)
		} else {
			return netcalc.ReadFrom(r, netC)
		}
	case "http", "https":
		resp, err := http.Get(feed)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("non-OK status code: %d", resp.StatusCode)
		}

		if strings.Contains(resp.Header.Get("Content-Type"), "/json") {
			return readFromJSON(resp.Body, netC)
		} else {
			return netcalc.ReadFrom(resp.Body, netC)
		}
	}

	return 0, fmt.Errorf("%w: %s", ErrUnhandledScheme, u.Scheme)
}

// parseFeeds parses feeds concurrently and returns summarized nets and the
// total nets prior to summarization.
func parseFeeds(feeds ...string) (nets netcalc.Nets, totalNets int) {
	// Parse all of the feeds concurrently
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

			i, err := readFeed(feed, netC)
			if err != nil {
				log.WithFields(log.Fields{
					"feed": feed,
				}).WithError(err).Error("Feed read error")
				return
			}

			if err != nil {
				log.WithFields(log.Fields{
					"feed": feed,
					"nets": i,
				}).WithError(err).Error("Feed parse error")
				return
			}

			log.WithFields(log.Fields{
				"feed": feed,
				"nets": i,
			}).Info("Feed parsed")
		}(f)
	}

	for n := range netC {
		nets = append(nets, n)
	}

	// Summarize the networks
	totalNets = len(nets)
	sort.Sort(nets)
	nets.Assim()
	nets.Aggr()

	return
}

// sblEntry represents a Spamhaus Block List entry.
type sblEntry struct {
	// IP network to drop, in CIDR format.
	CIDR string `json:"cidr"`

	// Regional Internet Registry that manages the network.
	RIR string `json:"rir"`

	// Spamhaus Block List identifier.
	SBLID string `json:"sblid"`
}

// readFromJSON parses the io.Reader as Spamhaus formatted JSONL and sends the
// resulting IPNets to the NetC channel.
func readFromJSON(r io.Reader, netC chan<- *net.IPNet) (int64, error) {
	d := json.NewDecoder(r)
	var i int64
	for ; ; i++ {
		var e sblEntry
		err := d.Decode(&e)
		if err == io.EOF {
			break
		} else if err != nil {
			return i, fmt.Errorf("line %d decode: %w", i, err)
		}
		if e.CIDR == "" {
			// Probably the footer line
			continue
		}

		_, n, err := netcalc.ParseNet(e.CIDR)
		if err != nil {
			return i, fmt.Errorf("line %d parse %q: %w", i, e.CIDR, err)
		}

		netC <- n
	}

	return i, nil
}
