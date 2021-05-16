// Copyright (c) 2021 Eric Barkie. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package main

//go:generate ./version.sh

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"
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
	conf := flag.String("conf", "gobgpd.conf", "GoBGP configuration file")
	debug := flag.Bool("debug", false, "Enable debug logging")
	var feeds urls
	flag.Var(&feeds, "feed", "Threat intelligence feed (use multiple times)")
	refreshRate := flag.Duration("refresh-rate", 120*time.Minute, "Refresh timer")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	log.Infof("Blackhole threats (version %s)", version)

	// Start BGP server.
	bh, err := NewServer(*conf)
	if err != nil {
		log.Fatal(err)
	}
	log.Info("Server started")

	// Update routes at refresh rate.
	bh.Feeds = feeds
	bh.RefreshRate = *refreshRate
	bh.SigC = make(chan os.Signal, 1)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	signal.Notify(bh.SigC, os.Signal(syscall.SIGUSR1))

	log.WithFields(log.Fields{
		"err": bh.UpdateRoutes(ctx),
	}).Info("Server stopped")
}
