// Copyright (c) 2024 Eric Barkie. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var ErrMalformedComm = errors.New("malformed community")

type Comm uint32

func (c Comm) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("%d:%d", uint16(c>>16), uint16(c))), nil
}

func (c Comm) String() string {
	s, _ := c.MarshalText()
	return string(s)
}

func (c *Comm) UnmarshalText(text []byte) error {
	parts := strings.Split(string(text), ":")
	if len(parts) != 2 {
		return ErrMalformedComm
	}

	upper, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return fmt.Errorf("%w: upper %s", ErrMalformedComm, err)
	}
	lower, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return fmt.Errorf("%w: lower %s", ErrMalformedComm, err)
	}

	*c = Comm(upper<<16 ^ lower)

	return nil
}

type FeedConfig struct {
	URL  string `yaml:"url"`
	Comm Comm   `yaml:"community"`
}

func (c FeedConfig) String() string {
	if c.Comm == 0 {
		return c.URL
	}

	return fmt.Sprintf("%s[%s]", c.URL, c.Comm)
}

type Config struct {
	Feeds []FeedConfig `yaml:"feeds"`
}

type feedSet []FeedConfig

func (f *feedSet) String() string {
	s := make([]string, len(*f))
	for i := range len(*f) {
		s[i] = (*f)[i].String()
	}

	return "[" + strings.Join(s, " ") + "]"
}

func (f *feedSet) Set(value string) error {
	*f = append(*f, FeedConfig{
		URL: value,
		// Use a feed config to set a custom community
	})
	return nil
}
