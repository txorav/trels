package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/http/httptest"
	"testing"
)

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
	// Setup test store
	recordsFile = "test_records.json" // Don't overwrite real records
	defer func() {
		localRecords = make(map[string]TrelsRecord)
	}()

	// Test invalid domain
	invalidRecord := TrelsRecord{Domain: "invalid domain", Port: 3000, Enabled: true}
	body, _ := json.Marshal(invalidRecord)
	req := httptest.NewRequest("POST", "/api/records", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	handleRecords(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for invalid domain, got %v", rr.Code)
	}
}

func TestTrafficStoreInit(t *testing.T) {
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

func TestBasicAuthProxyHandling(t *testing.T) {
	// Setup protected record in localRecords
	rec := TrelsRecord{
		Domain:      "auth.local",
		Port:        9090,
		Enabled:     true,
		AuthEnabled: true,
		AuthUser:    "user1",
		AuthPass:    "pass1",
	}
	mutex.Lock()
	localRecords[rec.Domain] = rec
	mutex.Unlock()
	defer func() {
		mutex.Lock()
		delete(localRecords, rec.Domain)
		mutex.Unlock()
	}()

	// 1. Request without auth
	req := httptest.NewRequest("GET", "http://auth.local/", nil)
	rr := httptest.NewRecorder()

	proxyHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized, got %v", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Error("Expected WWW-Authenticate header")
	}

	// 2. Request with invalid auth
	req = httptest.NewRequest("GET", "http://auth.local/", nil)
	req.SetBasicAuth("user1", "wrongpass")
	rr = httptest.NewRecorder()

	proxyHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 Unauthorized for invalid pass, got %v", rr.Code)
	}

	// 3. Request with valid auth (will attempt to reach target port 9090)
	// We check if it goes past auth checks and tries to serve proxy (returns 502 bad gateway since port 9090 is closed, which is expected)
	req = httptest.NewRequest("GET", "http://auth.local/", nil)
	req.SetBasicAuth("user1", "pass1")
	rr = httptest.NewRecorder()

	proxyHandler(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502 Bad Gateway (since port is closed), but got %v", rr.Code)
	}
}
