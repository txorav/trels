package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// setupTestEnv sets up temporary files for hosts and records, and resets global state.
func setupTestEnv(t *testing.T) (cleanup func()) {
	// Reset in-memory state
	resetStateForTest()

	// Create temp hosts file
	tmpHosts, err := os.CreateTemp("", "hosts-*")
	if err != nil {
		t.Fatalf("Failed to create temp hosts file: %v", err)
	}
	overrideHostsFilePath = tmpHosts.Name()

	// Create temp records file
	tmpRecords, err := os.CreateTemp("", "records-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp records file: %v", err)
	}
	recordsFile = tmpRecords.Name()

	// Setup environment variables for test admin creds
	os.Setenv("TRELS_ADMIN_USER", "testadmin")
	os.Setenv("TRELS_ADMIN_PASS", "testpass")

	return func() {
		os.Remove(tmpHosts.Name())
		os.Remove(tmpRecords.Name())
		overrideHostsFilePath = ""
		os.Unsetenv("TRELS_ADMIN_USER")
		os.Unsetenv("TRELS_ADMIN_PASS")
	}
}

// getTestAdminHandler returns the protected admin router
func getTestAdminHandler() http.Handler {
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/records", handleRecords)
	apiMux.HandleFunc("/api/records/toggle", handleToggle)
	apiMux.HandleFunc("/api/metrics", handleMetrics)
	apiMux.HandleFunc("/api/ports", handlePorts)
	apiMux.HandleFunc("/api/records/export", handleExport)
	apiMux.HandleFunc("/api/records/import", handleImport)
	return securityHeaders(basicAuth(apiMux))
}

func doAdminRequest(t *testing.T, server *httptest.Server, method, path string, body interface{}) *http.Response {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("Failed to marshal body: %v", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, server.URL+path, reqBody)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.SetBasicAuth("testadmin", "testpass")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to execute request: %v", err)
	}
	return resp
}

// ========== EXISTING UNIT TESTS ==========

func TestDomainRegex(t *testing.T) {
	valid := []string{"example.local", "test.com", "my-app.dev", "sub.domain.org"}
	invalid := []string{"ex ample", "test@domain", "app/local", "foo;bar"}

	for _, d := range valid {
		if !domainRegex.MatchString(d) {
			t.Errorf("Expected domain %s to be valid", d)
		}
	}

	for _, d := range invalid {
		if domainRegex.MatchString(d) {
			t.Errorf("Expected domain %s to be invalid", d)
		}
	}
}

func TestHandleRecordsValidation(t *testing.T) {
	cleanup := setupTestEnv(t)
	defer cleanup()

	// Test invalid domain
	invalidRecord := TrelsRecord{Domain: "invalid domain", Port: 3000, Enabled: true}
	body, _ := json.Marshal(invalidRecord)
	req := httptest.NewRequest("POST", "/api/records", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handleRecords(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for invalid domain, got %v", rr.Code)
	}
}

func TestTrafficStoreInit(t *testing.T) {
	cleanup := setupTestEnv(t)
	defer cleanup()

	// Add a record
	req := TrelsRecord{Domain: "monitor.local", Port: 8080, Enabled: true}
	
	mutex.Lock()
	localRecords[req.Domain] = req
	initTrackers(req.Domain)
	mutex.Unlock()

	mutex.RLock()
	stats := trafficStore["monitor.local"]
	mutex.RUnlock()

	if stats == nil {
		t.Errorf("Expected traffic stats to be initialized")
	}
}

func TestEncryptionDecryption(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32-byte key
	plaintext := []byte("Trels test secure plaintext data")

	ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Error("Ciphertext should not equal plaintext")
	}

	decrypted, err := decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted data %s does not match plaintext %s", string(decrypted), string(plaintext))
	}

	// Test invalid key
	wrongKey := []byte("wrongwrongwrongwrongwrongwrongwr")
	_, err = decrypt(ciphertext, wrongKey)
	if err == nil {
		t.Error("Decryption with wrong key should have failed")
	}
}

// ========== NEW E2E TESTS ==========

func TestAdminAPI_Unauthorized(t *testing.T) {
	cleanup := setupTestEnv(t)
	defer cleanup()

	handler := getTestAdminHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Test without auth
	resp, err := http.Get(server.URL + "/api/records")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestAdminAPI_CRUD(t *testing.T) {
	cleanup := setupTestEnv(t)
	defer cleanup()

	handler := getTestAdminHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// 1. Create a record
	newRecord := TrelsRecord{
		Domain:  "test.local",
		Port:    8081,
		Enabled: true,
	}
	resp := doAdminRequest(t, server, http.MethodPost, "/api/records", newRecord)
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status 201 Created, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 2. Get records
	resp = doAdminRequest(t, server, http.MethodGet, "/api/records", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d", resp.StatusCode)
	}
	var records []TrelsRecord
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	resp.Body.Close()

	if len(records) != 1 || records[0].Domain != "test.local" {
		t.Errorf("Expected 1 record with domain 'test.local', got: %+v", records)
	}

	// 3. Toggle record
	toggleReq := map[string]interface{}{"domain": "test.local", "enabled": false}
	resp = doAdminRequest(t, server, http.MethodPost, "/api/records/toggle", toggleReq)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 OK after toggle, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Verify toggled
	mutex.RLock()
	rec := localRecords["test.local"]
	mutex.RUnlock()
	if rec.Enabled {
		t.Errorf("Expected record to be disabled after toggle")
	}

	// 4. Delete record
	delReq := map[string]interface{}{"domain": "test.local"}
	resp = doAdminRequest(t, server, http.MethodDelete, "/api/records", delReq)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 OK after delete, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Verify deletion
	resp = doAdminRequest(t, server, http.MethodGet, "/api/records", nil)
	var recordsAfter []TrelsRecord
	json.NewDecoder(resp.Body).Decode(&recordsAfter)
	resp.Body.Close()
	if len(recordsAfter) != 0 {
		t.Errorf("Expected 0 records after deletion, got %d", len(recordsAfter))
	}
}

func TestProxy_RoutingAndRateLimit(t *testing.T) {
	cleanup := setupTestEnv(t)
	defer cleanup()

	// 1. Setup a dummy backend server
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Backend OK"))
	})
	backendServer := httptest.NewServer(backendHandler)
	defer backendServer.Close()

	var backendPort int
	fmt.Sscanf(strings.TrimPrefix(backendServer.URL, "http://127.0.0.1:"), "%d", &backendPort)

	// 2. Add record via Admin API (simulated)
	mutex.Lock()
	localRecords["testproxy.local"] = TrelsRecord{
		Domain:    "testproxy.local",
		Port:      backendPort,
		Enabled:   true,
		RateLimit: 2, // Max 2 requests per second
	}
	initTrackers("testproxy.local")
	mutex.Unlock()

	// 3. Setup proxy server
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/", proxyHandler)
	proxyServer := httptest.NewServer(proxyMux)
	defer proxyServer.Close()

	// 4. Test normal routing
	req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	req.Host = "testproxy.local"

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Proxy request failed: %v", err)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected proxy to return 200, got %d", resp.StatusCode)
	}
	if string(bodyBytes) != "Backend OK" {
		t.Errorf("Expected 'Backend OK', got '%s'", string(bodyBytes))
	}

	// 5. Test Rate Limiting
	// The rate limit is 2 req/s. We already made 1 request. Let's make 3 more.
	client.Do(req) // 2nd req - ok
	
	// 3rd req - should fail
	resp3, _ := client.Do(req)
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected status 429 Too Many Requests, got %d", resp3.StatusCode)
	}

	// 6. Test Metrics
	mutex.RLock()
	stats := trafficStore["testproxy.local"]
	mutex.RUnlock()

	// 1st request (ok), 2nd request (ok) -> both counted. 3rd request (rate limited) -> returns before incrementing stats.
	if stats == nil || stats.Requests < 2 {
		t.Errorf("Expected metrics to track at least 2 requests, got stats: %+v", stats)
	}
}

func TestProxy_BasicAuth(t *testing.T) {
	cleanup := setupTestEnv(t)
	defer cleanup()

	// 1. Add record with Basic Auth required
	mutex.Lock()
	localRecords["auth.local"] = TrelsRecord{
		Domain:      "auth.local",
		Port:        8080,
		Enabled:     true,
		AuthEnabled: true,
		AuthUser:    "secretuser",
		AuthPass:    "secretpass",
	}
	initTrackers("auth.local")
	mutex.Unlock()

	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/", proxyHandler)
	proxyServer := httptest.NewServer(proxyMux)
	defer proxyServer.Close()

	// 2. Request without auth
	req, _ := http.NewRequest(http.MethodGet, proxyServer.URL+"/", nil)
	req.Host = "auth.local"
	client := &http.Client{}
	
	resp, _ := client.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 without auth, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 3. Request with wrong auth
	req.SetBasicAuth("admin", "wrong")
	resp, _ = client.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 with wrong auth, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 4. Request with correct auth (should return Bad Gateway since no backend is running on 8080)
	req.SetBasicAuth("secretuser", "secretpass")
	resp, _ = client.Do(req)
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("Expected 502 Bad Gateway with correct auth, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
