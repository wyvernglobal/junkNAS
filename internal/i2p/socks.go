// Package i2p — socks.go
//
// Provides a pre-configured *http.Client that routes all requests through
// i2pd's SOCKS5 proxy on 127.0.0.1:4447. This is the single HTTP client
// used by every package that needs to reach a peer over I2P.
//
// Usage:
//
//	client := i2p.NewHTTPClient()
//	resp, err := client.Post("http://abc123.b32.i2p/v1/join", ...)
package i2p

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

const (
	// dialTimeout is how long to wait for the SOCKS5 dial to succeed.
	dialTimeout = 120 * time.Second // I2P latency can be high during bootstrap

	// requestTimeout is the overall HTTP request deadline.
	requestTimeout = 90 * time.Second
)

// NewHTTPClient returns an *http.Client whose transport dials all
// connections through i2pd's SOCKS5 proxy on 127.0.0.1:4447.
//
// The client should be created once at daemon startup and reused.
func NewHTTPClient() *http.Client {
	dialer, err := proxy.SOCKS5("tcp", SOCKS5Addr, nil, proxy.Direct)
	if err != nil {
		// proxy.SOCKS5 only fails on bad address format — panic is appropriate.
		panic(fmt.Sprintf("i2p: socks5 dialer: %v", err))
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Use the context deadline if it's tighter than dialTimeout.
			type contextDialer interface {
				DialContext(ctx context.Context, network, addr string) (net.Conn, error)
			}
			if cd, ok := dialer.(contextDialer); ok {
				return cd.DialContext(ctx, network, addr)
			}
			return dialer.Dial(network, addr)
		},
		// I2P .b32.i2p "hostnames" are resolved by the SOCKS5 proxy itself.
		DisableKeepAlives:   false,
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
	}
}

// WaitForSOCKS5 blocks until the i2pd SOCKS5 proxy is accepting connections
// or the context is cancelled. Used during startup to avoid sending requests
// before i2pd is ready.
func WaitForSOCKS5(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn, err := net.DialTimeout("tcp", SOCKS5Addr, 2*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
		}
	}
}
