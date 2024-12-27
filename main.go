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
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

func main() {
	// Parse flags
	conf := flag.String("conf", "blackhole-threats.yaml", "Configuration file")
	debug := flag.Bool("debug", false, "Enable debug logging")
	var feeds feedSet
	flag.Var(&feeds, "feed", "Threat intelligence feed (use multiple times)")
	refreshRate := flag.Duration("refresh-rate", 2*time.Hour, "Refresh timer")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	log.Infof("BGP threat blackhole route server (version %s)", version)

	// Parse configuration
	var c Config
	bs, err := os.ReadFile(*conf)
	if err != nil {
		log.WithError(err).Fatal("Unable to read feed config")
	}

	if err := yaml.Unmarshal(bs, &c); err != nil {
		log.WithError(err).Fatal("Unable to parse feed config")
	}

	feeds = append(feeds, c.Feeds...)

	// Start Blackhole server
	bh, err := NewServer(&c.GoBGP)
	if err != nil {
		log.Fatal(err)
	}
	log.Info("Server started")
	defer bh.Stop()

	// Update routes at refresh rate
	bh.Feeds = feeds
	bh.RefreshRate = *refreshRate
	bh.SigC = make(chan os.Signal, 1)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	signal.Notify(bh.SigC, os.Signal(syscall.SIGUSR1))

	log.WithError(bh.UpdateRoutes(ctx)).Info("Server stopped")

}
