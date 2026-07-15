package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func runBenchmark(name, url, host string, concurrency, durationSec int) {
	fmt.Printf("\n--- Starting Benchmark: %s ---\n", name)
	fmt.Printf("URL: %s (Host: %s)\n", url, host)
	fmt.Printf("Concurrency: %d, Duration: %ds\n", concurrency, durationSec)

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        concurrency,
			MaxIdleConnsPerHost: concurrency,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: 5 * time.Second,
	}

	var totalReqs int64
	var totalErrors int64
	var totalLatency int64 // microseconds

	var wg sync.WaitGroup
	endTime := time.Now().Add(time.Duration(durationSec) * time.Second)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(endTime) {
				req, _ := http.NewRequest(http.MethodGet, url, nil)
				if host != "" {
					req.Host = host
				}

				start := time.Now()
				resp, err := client.Do(req)
				latency := time.Since(start).Microseconds()

				if err != nil {
					atomic.AddInt64(&totalErrors, 1)
					time.Sleep(10 * time.Millisecond)
					continue
				}

				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					atomic.AddInt64(&totalReqs, 1)
					atomic.AddInt64(&totalLatency, latency)
				} else {
					atomic.AddInt64(&totalErrors, 1)
				}
			}
		}()
	}

	wg.Wait()

	reqs := atomic.LoadInt64(&totalReqs)
	errs := atomic.LoadInt64(&totalErrors)
	lat := atomic.LoadInt64(&totalLatency)

	reqPerSec := float64(reqs) / float64(durationSec)
	var avgLat float64
	if reqs > 0 {
		avgLat = float64(lat) / float64(reqs) / 1000.0 // milliseconds
	}

	fmt.Printf("Results for %s:\n", name)
	fmt.Printf("- Requests: %d (%.2f req/sec)\n", reqs, reqPerSec)
	fmt.Printf("- Errors: %d\n", errs)
	fmt.Printf("- Average Latency: %.2f ms\n", avgLat)
}

func TestProxyThroughput(t *testing.T) {
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Benchmarking Response"))
	})
	backendServer := httptest.NewServer(backendHandler)
	defer backendServer.Close()
	fmt.Printf("Dummy Backend running at %s\n", backendServer.URL)

	// Setup Trels internal state for 'odoo.local'
	var backendPort int
	fmt.Sscanf(backendServer.URL, "http://127.0.0.1:%d", &backendPort)

	mutex.Lock()
	localRecords["odoo.local"] = TrelsRecord{
		Domain:  "odoo.local",
		Port:    backendPort,
		Enabled: true,
	}
	initTrackers("odoo.local")
	mutex.Unlock()

	// Start Trels proxy
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/", proxyHandler)
	proxyServer := httptest.NewServer(proxyMux)
	defer proxyServer.Close()
	fmt.Printf("Trels Proxy running at %s\n", proxyServer.URL)

	concurrency := 100
	duration := 5

	runBenchmark("Direct (Localhost)", backendServer.URL, "", concurrency, duration)
	runBenchmark("Through Proxy (odoo.local)", proxyServer.URL, "odoo.local", concurrency, duration)
}
