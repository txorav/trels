package main

import (
	"bufio"
	"bytes"
	"crypto/subtle"
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
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

//go:embed all:admin_dist
var frontendAssets embed.FS

type TrelsRecord struct {
	Domain  string `json:"domain"`
	Port    int    `json:"port"`
	Enabled bool   `json:"enabled"`
}

type TrafficStats struct {
	Requests int64 `json:"requests"`
	BytesIn  int64 `json:"bytesIn"`
	BytesOut int64 `json:"bytesOut"`
}

type PortInfo struct {
	Port    int    `json:"port"`
	Process string `json:"process"`
}

var (
	mutex        sync.RWMutex
	recordsFile  string
	localRecords = make(map[string]TrelsRecord)
	trafficStore = make(map[string]*TrafficStats)
	domainRegex  = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
)

func init() {
	// Security: Use absolute path for records.json relative to the executable
	exePath, err := os.Executable()
	if err == nil {
		recordsFile = filepath.Join(filepath.Dir(exePath), "records.json")
	} else {
		recordsFile = "records.json" // fallback
	}
}

// Security: Basic Auth Middleware
func basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		// In a real production app, you would hash these or load from env
		expectedUser := []byte("admin")
		expectedPass := []byte("admin")

		if !ok || subtle.ConstantTimeCompare([]byte(user), expectedUser) != 1 || subtle.ConstantTimeCompare([]byte(pass), expectedPass) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func getHostsFilePath() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	return "/etc/hosts"
}

func loadRecords() {
	mutex.Lock()
	defer mutex.Unlock()
	data, err := os.ReadFile(recordsFile)
	if err == nil {
		var arr []TrelsRecord
		if err := json.Unmarshal(data, &arr); err == nil {
			for _, r := range arr {
				localRecords[r.Domain] = r
				if trafficStore[r.Domain] == nil {
					trafficStore[r.Domain] = &TrafficStats{}
				}
			}
		}
	}
}

func saveRecords() error {
	var arr []TrelsRecord
	for _, r := range localRecords {
		arr = append(arr, r)
	}
	data, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(recordsFile, data, 0600) // Security: strict permissions
}

func syncHostsFile() error {
	path := getHostsFilePath()
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read hosts file (run as Administrator/root): %v", err)
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	inTrelsSection := false

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

	for len(newLines) > 0 && strings.TrimSpace(newLines[len(newLines)-1]) == "" {
		newLines = newLines[:len(newLines)-1]
	}

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
	newLines = append(newLines, "")

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

		if !domainRegex.MatchString(req.Domain) {
			http.Error(w, "Invalid domain name", http.StatusBadRequest)
			return
		}

		mutex.Lock()
		localRecords[req.Domain] = req
		if trafficStore[req.Domain] == nil {
			trafficStore[req.Domain] = &TrafficStats{}
		}
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

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	mutex.RLock()
	defer mutex.RUnlock()
	json.NewEncoder(w).Encode(trafficStore)
}

func getOpenPorts() []PortInfo {
	var ports []PortInfo
	portSet := make(map[int]bool)

	if runtime.GOOS == "windows" {
		cmd := exec.Command("netstat", "-ano")
		out, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(out))
			for scanner.Scan() {
				line := strings.Fields(scanner.Text())
				if len(line) >= 4 && line[0] == "TCP" && strings.Contains(line[3], "LISTENING") {
					parts := strings.Split(line[1], ":")
					portStr := parts[len(parts)-1]
					port, _ := strconv.Atoi(portStr)
					
					if port > 0 && !portSet[port] {
						ports = append(ports, PortInfo{Port: port, Process: fmt.Sprintf("PID: %s", line[4])})
						portSet[port] = true
					}
				}
			}
		}
	} else {
		cmd := exec.Command("ss", "-tlnp")
		out, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(out))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, "LISTEN") {
					fields := strings.Fields(line)
					if len(fields) >= 4 {
						parts := strings.Split(fields[3], ":")
						portStr := parts[len(parts)-1]
						port, _ := strconv.Atoi(portStr)
						
						process := "Unknown"
						if len(fields) >= 6 && strings.Contains(fields[5], "users:((") {
							procParts := strings.Split(fields[5], "\"")
							if len(procParts) >= 2 {
								process = procParts[1]
							}
						}
						if port > 0 && !portSet[port] {
							ports = append(ports, PortInfo{Port: port, Process: process})
							portSet[port] = true
						}
					}
				}
			}
		}
	}
	return ports
}

func handlePorts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ports := getOpenPorts()
	json.NewEncoder(w).Encode(ports)
}

func startServerWithFallback(startPort int, bindIP string, handler http.Handler, name string) {
	port := startPort
	for {
		addr := fmt.Sprintf("%s:%d", bindIP, port)
		if bindIP == "" {
			addr = fmt.Sprintf(":%d", port)
		}
		
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			port++
			continue
		}
		fmt.Printf("[%s] Listening on %s\n", name, addr)
		go http.Serve(listener, handler)
		break
	}
}

type trackingWriter struct {
	http.ResponseWriter
	bytesWritten int64
}

func (w *trackingWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.bytesWritten += int64(n)
	return n, err
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}

	mutex.RLock()
	rec, exists := localRecords[host]
	stats := trafficStore[host]
	mutex.RUnlock()

	if !exists || !rec.Enabled {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Trels: Domain '%s' not found or not enabled.", host)
		return
	}

	if stats != nil {
		mutex.Lock()
		stats.Requests++
		stats.BytesIn += r.ContentLength
		if stats.BytesIn < 0 {
			stats.BytesIn = 0
		}
		mutex.Unlock()
	}

	targetURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", rec.Port))
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, "Trels Proxy Error: Could not reach local port %d for domain %s\nError: %v", rec.Port, rec.Domain, err)
	}

	tw := &trackingWriter{ResponseWriter: w}
	proxy.ServeHTTP(tw, r)

	if stats != nil {
		mutex.Lock()
		stats.BytesOut += tw.bytesWritten
		mutex.Unlock()
	}
}

func main() {
	fmt.Println("Trels Backend starting...")
	fmt.Printf("Using configuration file: %s\n", recordsFile)
	loadRecords()
	
	if err := syncHostsFile(); err != nil {
		fmt.Println("Warning: Could not sync hosts file initially (run as Administrator/root for full functionality).")
	}

	// Proxy can listen on all interfaces
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/", proxyHandler)
	startServerWithFallback(80, "0.0.0.0", proxyMux, "Reverse Proxy")

	// Admin API MUST be secured with Basic Auth
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/records", handleRecords)
	apiMux.HandleFunc("/api/records/toggle", handleToggle)
	apiMux.HandleFunc("/api/metrics", handleMetrics)
	apiMux.HandleFunc("/api/ports", handlePorts)

	subFS, err := fs.Sub(frontendAssets, "admin_dist")
	if err != nil {
		log.Fatal(err)
	}
	// Serve static files with auth too
	apiMux.Handle("/", http.FileServer(http.FS(subFS)))

	secureMux := basicAuth(apiMux)

	fmt.Println("Starting Admin Panel search...")
	// Security: Admin panel strictly binds to localhost (127.0.0.1)
	startServerWithFallback(8080, "127.0.0.1", secureMux, "Admin Panel")

	select {}
}
