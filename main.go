// Copyright (c) 2021 Eric Barkie. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type urls []string

func (u *urls) String() string {
	return "[" + strings.Join(*u, " ") + "]"
}

func (u *urls) Set(value string) error {
	*u = append(*u, value)
	return nil
}

func main() {
	// Parse flags.
	configFile := flag.String("f", "gobgpd.conf", "GoBGP configuration file")
	debug := flag.Bool("debug", false, "Enable debug logging")
	var feeds urls
	flag.Var(&feeds, "feed", "Threat intelligence feed (use multiple times)")
	refreshRate := flag.Duration("refresh-rate", 60*time.Minute, "Refresh timer")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	// Start BGP server.
	bh, err := NewServer(*configFile)
	if err != nil {
		log.Fatal(err)
	}
	log.Info("Server started")

	// Update routes at refresh rate.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bh.RefreshRate = *refreshRate
	bh.Feeds = feeds
	log.WithFields(log.Fields{
		"err": bh.UpdateRoutes(ctx),
	}).Info("Server stopped")
}
