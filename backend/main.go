package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
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
	"time"
)

//go:embed all:admin_dist
var frontendAssets embed.FS

const AppVersion = "v0.1.6"
const MaxBodySize = 1 << 20 // 1MB

type TrelsRecord struct {
	Domain      string `json:"domain"`
	Port        int    `json:"port"`
	Enabled     bool   `json:"enabled"`
	HTTPS       bool   `json:"https"`
	RateLimit   int    `json:"rateLimit"`
	AuthEnabled bool   `json:"authEnabled"`
	AuthUser    string `json:"authUser"`
	AuthPass    string `json:"authPass"`
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

type RateLimiter struct {
	Count     int
	Timestamp int64
	Mutex     sync.Mutex
}

var (
	mutex          sync.RWMutex
	recordsFile    string
	localRecords   = make(map[string]TrelsRecord)
	trafficStore   = make(map[string]*TrafficStats)
	rateLimitStore = make(map[string]*RateLimiter)
	domainRegex    = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
	updateClient   = &http.Client{Timeout: 60 * time.Second}
)

func init() {
	exePath, err := os.Executable()
	if err == nil {
		recordsFile = filepath.Join(filepath.Dir(exePath), "records.json")
	} else {
		recordsFile = "records.json"
	}
}

// ========== MACHINE-LEVEL ENCRYPTION UTILS ==========

func getMachineID() string {
	if runtime.GOOS == "windows" {
		regPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "reg.exe")
		cmd := exec.Command(regPath, "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid")
		out, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				if strings.Contains(line, "MachineGuid") {
					fields := strings.Fields(line)
					if len(fields) >= 3 {
						return fields[2]
					}
				}
			}
		}
	} else {
		// Linux
		for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			data, err := os.ReadFile(path)
			if err == nil {
				return strings.TrimSpace(string(data))
			}
		}
	}
	return "fallback-trels-encryption-key-static"
}

func getEncryptionKey() []byte {
	id := getMachineID()
	hash := sha256.Sum256([]byte(id))
	return hash[:]
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, actualCiphertext, nil)
}

// ========== AUTOMATIC CERTIFICATE TRUSTING ==========

func trustCertificate(certPath string) {
	if runtime.GOOS == "windows" {
		certutilPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "certutil.exe")
		cmd := exec.Command(certutilPath, "-addstore", "-f", "Root", certPath)
		if err := cmd.Run(); err != nil {
			fmt.Printf("Warning: Failed to auto-trust root certificate on Windows: %v\n", err)
		} else {
			fmt.Println("Successfully trusted self-signed root certificate in Windows store.")
		}
	} else {
		// Linux auto-trust
		if _, err := os.Stat("/etc/debian_version"); err == nil {
			target := "/usr/local/share/ca-certificates/trels.crt"
			if err := copyFile(certPath, target); err == nil {
				cmd := exec.Command("/usr/sbin/update-ca-certificates")
				if err := cmd.Run(); err == nil {
					fmt.Println("Successfully trusted certificate on Debian/Ubuntu.")
				}
			}
		} else if _, err := os.Stat("/etc/redhat-release"); err == nil {
			target := "/etc/pki/ca-trust/source/anchors/trels.crt"
			if err := copyFile(certPath, target); err == nil {
				cmd := exec.Command("/usr/bin/update-ca-trust", "extract")
				if err := cmd.Run(); err == nil {
					fmt.Println("Successfully trusted certificate on RHEL/CentOS/Fedora.")
				}
			}
		}
	}
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// ========== HTTP BASIC AUTH MIDDLEWARE (ADMIN PANEL) ==========

func getAdminCredentials() ([]byte, []byte) {
	user := os.Getenv("TRELS_ADMIN_USER")
	pass := os.Getenv("TRELS_ADMIN_PASS")
	if user == "" {
		user = "admin"
	}
	if pass == "" {
		pass = "admin"
		fmt.Println("WARNING: Using default admin credentials. Set TRELS_ADMIN_USER and TRELS_ADMIN_PASS environment variables for production use.")
	}
	return []byte(user), []byte(pass)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func basicAuth(next http.Handler) http.Handler {
	expectedUser, expectedPass := getAdminCredentials()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()

		if !ok || subtle.ConstantTimeCompare([]byte(user), expectedUser) != 1 || subtle.ConstantTimeCompare([]byte(pass), expectedPass) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ========== LOCAL STORAGE LOGIC ==========

var overrideHostsFilePath string

func getHostsFilePath() string {
	if overrideHostsFilePath != "" {
		return overrideHostsFilePath
	}
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32\drivers\etc\hosts`
	}
	return "/etc/hosts"
}

// resetStateForTest is a helper for unit testing to reset global state
func resetStateForTest() {
	mutex.Lock()
	defer mutex.Unlock()
	localRecords = make(map[string]TrelsRecord)
	trafficStore = make(map[string]*TrafficStats)
	rateLimitStore = make(map[string]*RateLimiter)
}

func initTrackers(domain string) {
	if trafficStore[domain] == nil {
		trafficStore[domain] = &TrafficStats{}
	}
	if rateLimitStore[domain] == nil {
		rateLimitStore[domain] = &RateLimiter{}
	}
}

func loadRecords() {
	mutex.Lock()
	defer mutex.Unlock()
	data, err := os.ReadFile(recordsFile)
	if err != nil {
		return // File doesn't exist yet
	}

	key := getEncryptionKey()
	decrypted, err := decrypt(data, key)
	if err != nil {
		// Decryption failed. Try parsing as raw unencrypted JSON for migration/import purposes
		var arr []TrelsRecord
		if err := json.Unmarshal(data, &arr); err == nil {
			fmt.Println("Migrating plain-text records.json to encrypted format...")
			for _, r := range arr {
				localRecords[r.Domain] = r
				initTrackers(r.Domain)
			}
			saveRecordsLocked()
			return
		}
		fmt.Printf("Warning: Failed to decrypt records database: %v\n", err)
		return
	}

	var arr []TrelsRecord
	if err := json.Unmarshal(decrypted, &arr); err == nil {
		for _, r := range arr {
			localRecords[r.Domain] = r
			initTrackers(r.Domain)
		}
	}
}

func saveRecords() error {
	mutex.Lock()
	defer mutex.Unlock()
	return saveRecordsLocked()
}

func saveRecordsLocked() error {
	var arr []TrelsRecord
	for _, r := range localRecords {
		arr = append(arr, r)
	}
	plaintext, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		return err
	}
	key := getEncryptionKey()
	ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		return err
	}
	return os.WriteFile(recordsFile, ciphertext, 0600)
}

func syncHostsFile() error {
	path := getHostsFilePath()
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read hosts file: %v", err)
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

// ========== RECORD CRUD ENDPOINTS ==========

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
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "Invalid Content-Type", http.StatusUnsupportedMediaType)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodySize)
		var req TrelsRecord
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if !domainRegex.MatchString(req.Domain) || len(req.Domain) > 253 {
			http.Error(w, "Invalid domain name", http.StatusBadRequest)
			return
		}

		if req.Port < 1 || req.Port > 65535 {
			http.Error(w, "Invalid port number", http.StatusBadRequest)
			return
		}

		mutex.Lock()
		localRecords[req.Domain] = req
		initTrackers(req.Domain)
		err := saveRecordsLocked()
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
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "Invalid Content-Type", http.StatusUnsupportedMediaType)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodySize)
		var req struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		
		mutex.Lock()
		delete(localRecords, req.Domain)
		delete(trafficStore, req.Domain)
		delete(rateLimitStore, req.Domain)
		saveRecordsLocked()
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
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Invalid Content-Type", http.StatusUnsupportedMediaType)
		return
	}
	var req struct {
		Domain  string `json:"domain"`
		Enabled bool   `json:"enabled"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	if rec, exists := localRecords[req.Domain]; exists {
		rec.Enabled = req.Enabled
		localRecords[req.Domain] = rec
		saveRecordsLocked()
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

// ========== EXPORT / IMPORT LOGIC ==========

func handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mutex.RLock()
	var arr []TrelsRecord
	for _, rec := range localRecords {
		// Strip auth credentials from export to prevent credential leakage
		safe := rec
		safe.AuthUser = ""
		safe.AuthPass = ""
		arr = append(arr, safe)
	}
	mutex.RUnlock()

	data, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		http.Error(w, "Export failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=trels-export.json")
	w.Write(data)
}

func handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Invalid Content-Type", http.StatusUnsupportedMediaType)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxBodySize)
	var arr []TrelsRecord
	if err := json.NewDecoder(r.Body).Decode(&arr); err != nil {
		http.Error(w, "Invalid JSON data", http.StatusBadRequest)
		return
	}

	if len(arr) > 1000 {
		http.Error(w, "Too many records in import (max 1000)", http.StatusBadRequest)
		return
	}

	for _, r := range arr {
		if !domainRegex.MatchString(r.Domain) {
			http.Error(w, fmt.Sprintf("Invalid domain in export: %s", r.Domain), http.StatusBadRequest)
			return
		}
		if r.Port < 1 || r.Port > 65535 {
			http.Error(w, fmt.Sprintf("Invalid port in export for %s: %d", r.Domain, r.Port), http.StatusBadRequest)
			return
		}
	}

	mutex.Lock()
	localRecords = make(map[string]TrelsRecord)
	for _, r := range arr {
		localRecords[r.Domain] = r
		initTrackers(r.Domain)
	}
	err := saveRecordsLocked()
	mutex.Unlock()

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to save imported records: %v", err), http.StatusInternalServerError)
		return
	}

	mutex.Lock()
	err = syncHostsFile()
	mutex.Unlock()

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to sync hosts file: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "count": len(arr)})
}

// ========== PORT SCANNER ==========

func getOpenPorts() []PortInfo {
	var ports []PortInfo
	portSet := make(map[int]bool)

	if runtime.GOOS == "windows" {
		netstatPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "netstat.exe")
		cmd := exec.Command(netstatPath, "-ano")
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
		cmd := exec.Command("/usr/bin/ss", "-tlnp")
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
	maxAttempts := 100
	for i := 0; i < maxAttempts; i++ {
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
		
		srv := &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		go srv.Serve(listener)
		return
	}
	fmt.Printf("[%s] FATAL: Could not bind to any port after %d attempts starting from %d\n", name, maxAttempts, startPort)
}

// ========== REVERSE PROXY LOGIC ==========

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
	rl := rateLimitStore[host]
	mutex.RUnlock()

	if !exists || !rec.Enabled {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Trels: Domain '%s' not found or not enabled.", host)
		return
	}

	// 1. Force HTTPS redirect
	if rec.HTTPS && r.TLS == nil {
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
		return
	}

	// 2. Per-mapping Basic Auth Check
	if rec.AuthEnabled {
		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(rec.AuthUser)) != 1 || subtle.ConstantTimeCompare([]byte(pass), []byte(rec.AuthPass)) != 1 {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="trels-%s"`, host))
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized mapping access\n"))
			return
		}
	}

	// 3. Rate Limiting Check
	if rec.RateLimit > 0 && rl != nil {
		rl.Mutex.Lock()
		now := time.Now().Unix()
		if rl.Timestamp != now {
			rl.Timestamp = now
			rl.Count = 0
		}
		rl.Count++
		if rl.Count > rec.RateLimit {
			rl.Mutex.Unlock()
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintf(w, "Trels: Rate limit exceeded for domain '%s'. Maximum %d req/s allowed.", host, rec.RateLimit)
			return
		}
		rl.Mutex.Unlock()
	}

	// 4. Update metrics requests
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
		fmt.Fprint(w, "Bad Gateway: The upstream service is unavailable.")
	}

	tw := &trackingWriter{ResponseWriter: w}
	proxy.ServeHTTP(tw, r)

	if stats != nil {
		mutex.Lock()
		stats.BytesOut += tw.bytesWritten
		mutex.Unlock()
	}
}

// ========== CERTIFICATE HANDLER ==========

func ensureCerts() (string, string, error) {
	certPath := filepath.Join(filepath.Dir(recordsFile), "cert.pem")
	keyPath := filepath.Join(filepath.Dir(recordsFile), "key.pem")

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			// Certificates already exist. Let's make sure they are trusted anyway.
			trustCertificate(certPath)
			return certPath, keyPath, nil 
		}
	}

	fmt.Println("Generating self-signed wildcard certificate for Trels...")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Trels Proxy"},
			CommonName:   "Trels Local Proxy",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "*.local"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %v", err)
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to open cert.pem for writing: %v", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", fmt.Errorf("failed to open key.pem for writing: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("unable to marshal private key: %v", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	keyOut.Close()

	// Trust newly created certificate
	trustCertificate(certPath)

	return certPath, keyPath, nil
}

func startHTTPSServerWithFallback(startPort int, bindIP string, handler http.Handler, name string, certFile string, keyFile string) {
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
		fmt.Printf("[%s] Listening on %s (HTTPS)\n", name, addr)
		
		srv := &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		go srv.ServeTLS(listener, certFile, keyFile)
		break
	}
}

// ========== MAIN ==========

func main() {
	fmt.Println("Trels Backend starting...")
	fmt.Printf("Using configuration file: %s\n", recordsFile)
	loadRecords()
	
	exe, err := os.Executable()
	if err == nil {
		os.Remove(exe + ".old")
	}
	
	if err := syncHostsFile(); err != nil {
		fmt.Println("Warning: Could not sync hosts file initially.")
	}

	certPath, keyPath, err := ensureCerts()
	if err != nil {
		fmt.Println("Warning: Could not generate HTTPS certificates:", err)
	}

	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/", proxyHandler)
	startServerWithFallback(80, "0.0.0.0", proxyMux, "HTTP Proxy")
	if err == nil {
		startHTTPSServerWithFallback(443, "0.0.0.0", proxyMux, "HTTPS Proxy", certPath, keyPath)
	}

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/records", handleRecords)
	apiMux.HandleFunc("/api/records/toggle", handleToggle)
	apiMux.HandleFunc("/api/metrics", handleMetrics)
	apiMux.HandleFunc("/api/ports", handlePorts)
	apiMux.HandleFunc("/api/records/export", handleExport)
	apiMux.HandleFunc("/api/records/import", handleImport)
	apiMux.HandleFunc("/api/version", handleVersion)
	apiMux.HandleFunc("/api/update", handleUpdate)

	subFS, fsErr := fs.Sub(frontendAssets, "admin_dist")
	if fsErr != nil {
		log.Fatal("Failed to load frontend assets: ", fsErr)
	}
	
	apiMux.Handle("/", http.FileServer(http.FS(subFS)))
	secureMux := securityHeaders(basicAuth(apiMux))

	fmt.Println("Starting Admin Panel search...")
	startServerWithFallback(8080, "127.0.0.1", secureMux, "Admin Panel")
	
	select {}
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"version": AppVersion})
}

func handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Fetch latest release with timeout-protected client
	resp, err := updateClient.Get("https://api.github.com/repos/txorav/trels/releases/latest")
	if err != nil {
		http.Error(w, "Failed to check updates", 500)
		return
	}
	defer resp.Body.Close()
	
	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, MaxBodySize)).Decode(&release); err != nil {
		http.Error(w, "Failed to parse updates", 500)
		return
	}
	
	if release.TagName == AppVersion {
		json.NewEncoder(w).Encode(map[string]bool{"updated": false})
		return
	}
	
	assetName := fmt.Sprintf("trels-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		assetName += ".exe"
	}
	
	var downloadURL string
	for _, a := range release.Assets {
		if a.Name == assetName {
			downloadURL = a.BrowserDownloadURL
			break
		}
	}
	
	if downloadURL == "" {
		http.Error(w, "No update asset found for this platform", 404)
		return
	}
	
	// Validate download URL is from our GitHub repo to prevent redirect hijacking
	if !strings.HasPrefix(downloadURL, "https://github.com/txorav/trels/") {
		http.Error(w, "Untrusted download source", 403)
		return
	}
	
	// Download with timeout-protected client
	dResp, err := updateClient.Get(downloadURL)
	if err != nil || dResp.StatusCode != 200 {
		http.Error(w, "Failed to download update", 500)
		return
	}
	defer dResp.Body.Close()
	
	exePath, err := os.Executable()
	if err != nil {
		http.Error(w, "Failed to get executable path", 500)
		return
	}
	
	newPath := exePath + ".new"
	out, err := os.OpenFile(newPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		http.Error(w, "Failed to prepare update file", 500)
		return
	}
	
	if _, err := io.Copy(out, dResp.Body); err != nil {
		out.Close()
		os.Remove(newPath)
		http.Error(w, "Failed to apply update", 500)
		return
	}
	out.Close() // Close before renaming
	
	if runtime.GOOS == "windows" {
		os.Rename(exePath, exePath+".old")
	}
	
	if err := os.Rename(newPath, exePath); err != nil {
		if runtime.GOOS == "windows" {
			os.Rename(exePath+".old", exePath)
		}
		http.Error(w, "Failed to replace executable", 500)
		return
	}
	
	json.NewEncoder(w).Encode(map[string]bool{"updated": true})
}
