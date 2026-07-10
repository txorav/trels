package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
)

//go:embed all:../frontend/admin
var frontendAssets embed.FS

type TrelsRecord struct {
	Domain  string `json:"domain"`
	Port    int    `json:"port"`
	Enabled bool   `json:"enabled"`
}

var (
	mutex        sync.RWMutex
	recordsFile  = "records.json"
	localRecords = make(map[string]TrelsRecord)
)

func getHostsFilePath() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	return "/etc/hosts"
}

// Load records from JSON
func loadRecords() {
	mutex.Lock()
	defer mutex.Unlock()

	data, err := os.ReadFile(recordsFile)
	if err == nil {
		var arr []TrelsRecord
		if err := json.Unmarshal(data, &arr); err == nil {
			for _, r := range arr {
				localRecords[r.Domain] = r
			}
		}
	}
}

// Save records to JSON
func saveRecords() error {
	var arr []TrelsRecord
	for _, r := range localRecords {
		arr = append(arr, r)
	}
	data, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(recordsFile, data, 0644)
}

// Sync enabled records with the OS hosts file
func syncHostsFile() error {
	path := getHostsFilePath()
	content, err := os.ReadFile(path)
	if err != nil {
		// If it doesn't exist or permissions fail, just return the error
		return fmt.Errorf("failed to read hosts file (run as Administrator/root): %v", err)
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	inTrelsSection := false

	// Filter out the old Trels section
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "# --- BEGIN TRELS RECORDS ---" {
			inTrelsSection = true
			continue
		}
		if trimmed == "# --- END TRELS RECORDS ---" {
			inTrelsSection = false
			continue
		}
		if !inTrelsSection {
			newLines = append(newLines, line)
		}
	}

	// Clean trailing empty lines
	for len(newLines) > 0 && strings.TrimSpace(newLines[len(newLines)-1]) == "" {
		newLines = newLines[:len(newLines)-1]
	}

	// Append the new Trels section if we have enabled records
	hasActive := false
	var trelsBlock []string
	trelsBlock = append(trelsBlock, "", "# --- BEGIN TRELS RECORDS ---")
	
	for _, rec := range localRecords {
		if rec.Enabled {
			hasActive = true
			trelsBlock = append(trelsBlock, fmt.Sprintf("127.0.0.1\t%s", rec.Domain))
		}
	}
	trelsBlock = append(trelsBlock, "# --- END TRELS RECORDS ---")

	if hasActive {
		newLines = append(newLines, trelsBlock...)
	}
	newLines = append(newLines, "") // trailing newline

	err = os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0644)
	if err != nil {
		return fmt.Errorf("failed to write to hosts file: %v", err)
	}
	return nil
}

func handleRecords(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		mutex.RLock()
		var arr []TrelsRecord
		for _, rec := range localRecords {
			arr = append(arr, rec)
		}
		mutex.RUnlock()
		json.NewEncoder(w).Encode(arr)
		return
	}

	if r.Method == http.MethodPost {
		var req TrelsRecord
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		mutex.Lock()
		localRecords[req.Domain] = req
		err := saveRecords()
		mutex.Unlock()

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		mutex.Lock()
		err = syncHostsFile()
		mutex.Unlock()

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
		return
	}

	if r.Method == http.MethodDelete {
		var req struct {
			Domain string `json:"domain"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		
		mutex.Lock()
		delete(localRecords, req.Domain)
		saveRecords()
		err := syncHostsFile()
		mutex.Unlock()

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		return
	}
}

func handleToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Domain  string `json:"domain"`
		Enabled bool   `json:"enabled"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	mutex.Lock()
	if rec, exists := localRecords[req.Domain]; exists {
		rec.Enabled = req.Enabled
		localRecords[req.Domain] = rec
		saveRecords()
		err := syncHostsFile()
		mutex.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	mutex.Unlock()
	http.Error(w, "Domain not found", http.StatusNotFound)
}

// startServerWithFallback tries ports sequentially starting from startPort
func startServerWithFallback(startPort int, handler http.Handler, name string) {
	port := startPort
	for {
		addr := fmt.Sprintf(":%d", port)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			port++
			continue
		}
		fmt.Printf("[%s] Listening on port %d\n", name, port)
		go http.Serve(listener, handler)
		break
	}
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}

	mutex.RLock()
	rec, exists := localRecords[host]
	mutex.RUnlock()

	if !exists || !rec.Enabled {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Trels: Domain '%s' not found or not enabled.", host)
		return
	}

	targetURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", rec.Port))
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	
	// Optional: rewrite response errors
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, "Trels Proxy Error: Could not reach local port %d for domain %s\nError: %v", rec.Port, rec.Domain, err)
	}

	proxy.ServeHTTP(w, r)
}

func main() {
	fmt.Println("Trels Backend starting...")
	loadRecords()
	
	// Initial Sync
	if err := syncHostsFile(); err != nil {
		fmt.Println("Warning: Could not sync hosts file initially (run as Administrator/root for full functionality).")
	}

	// Reverse Proxy Server Setup
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/", proxyHandler)
	startServerWithFallback(80, proxyMux, "Reverse Proxy")

	// Admin API & Static Files Setup
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/api/records", handleRecords)
	adminMux.HandleFunc("/api/records/toggle", handleToggle)

	subFS, err := fs.Sub(frontendAssets, "../frontend/admin")
	if err != nil {
		log.Fatal(err)
	}
	adminMux.Handle("/", http.FileServer(http.FS(subFS)))

	fmt.Println("Starting Admin Panel search...")
	startServerWithFallback(8080, adminMux, "Admin Panel")

	// Block main thread
	select {}
}
