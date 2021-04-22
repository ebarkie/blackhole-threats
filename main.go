// Copyright (c) 2021 Eric Barkie. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strings"
	"time"
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
	var e exaBGP
	flag.UintVar(&e.asn, "asn", 64512, "Autonomous System Number between 64512-65534")
	flag.StringVar(&e.nextHop, "nexthop", "192.168.0.254", "Next hop for routes")
	refreshRate := flag.Duration("refresh-rate", 60*time.Minute, "Refresh timer")
	var feeds urls
	flag.Var(&feeds, "feed", "Threat intelligence feed (use multiple times)")
	flag.Parse()

	// Set logging to stderr so it doesn't interfere with the API.
	log.SetOutput(os.Stderr)

	// Update routes.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.updateRoutes(ctx, *refreshRate, feeds)

	// Block receiving messages until stdin is closed.
	log.Printf("Receive closed with err = %v", recvMsgs())
}
