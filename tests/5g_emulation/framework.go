package main

import (
	"log"
	"time"

	toxiproxy "github.com/Shopify/toxiproxy/v2/client"
)

// EmulationFramework sets up Toxiproxy for URLLC testing.
type EmulationFramework struct {
	Client *toxiproxy.Client
	Proxy  *toxiproxy.Proxy
}

// NewEmulationFramework initializes the Toxiproxy client and creates a target proxy.
// It assumes Toxiproxy is running locally on port 8474.
func NewEmulationFramework(proxyName, listenAddr, upstreamAddr string) (*EmulationFramework, error) {
	client := toxiproxy.NewClient("localhost:8474")

	// Clean up existing proxy if it exists
	if p, err := client.Proxy(proxyName); err == nil {
		p.Delete()
	}

	proxy, err := client.CreateProxy(proxyName, listenAddr, upstreamAddr)
	if err != nil {
		return nil, err
	}

	return &EmulationFramework{
		Client: client,
		Proxy:  proxy,
	}, nil
}

// Reset clears all toxics from the proxy.
func (f *EmulationFramework) Reset() error {
	toxics, err := f.Proxy.Toxics()
	if err != nil {
		return err
	}
	for _, toxic := range toxics {
		if err := f.Proxy.RemoveToxic(toxic.Name); err != nil {
			log.Printf("Failed to remove toxic %s: %v", toxic.Name, err)
		}
	}
	return nil
}

// ApplyURLLC applies strict <1ms latency constraints.
func (f *EmulationFramework) ApplyURLLC() error {
	_, err := f.Proxy.AddToxic("urllc_latency", "latency", "downstream", 1.0, toxiproxy.Attributes{
		"latency": 0,    // Base latency in ms
		"jitter":  1,    // Max 1ms jitter
	})
	return err
}

// ApplyRANJitter emulates 5G RAN micro-bursts and out-of-order packets.
func (f *EmulationFramework) ApplyRANJitter() error {
	// Add extreme jitter
	_, err := f.Proxy.AddToxic("ran_jitter", "latency", "downstream", 1.0, toxiproxy.Attributes{
		"latency": 5,
		"jitter":  20,
	})
	return err
}

// EmulateHandover simulates a mobile edge handover by tearing down the connection and waiting.
func (f *EmulationFramework) EmulateHandover(downtime time.Duration) error {
	// Disable proxy to drop connections
	f.Proxy.Disable()
	time.Sleep(downtime)
	return f.Proxy.Enable()
}

func init() {
    log.Println("5G URLLC Emulation Framework initialized.")
}
