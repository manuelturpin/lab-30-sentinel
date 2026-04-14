// SAFE: Properly configured TLS and authentication
// These should NOT trigger detection patterns

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

// SAFE: TLS with proper certificate verification
func secureClient() *http.Client {
	caCert, _ := os.ReadFile("/etc/ssl/certs/ca-certificates.crt")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    caCertPool,
			MinVersion: tls.VersionTLS12,
		},
	}
	return &http.Client{Transport: transport}
}

// SAFE: Strong TLS configuration
func secureTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

// SAFE: Authentication middleware present
func requireAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if !verifyToken(token) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SAFE: Admin handler with auth
func adminHandler(w http.ResponseWriter, r *http.Request) {
	// Auth is handled by middleware
	fmt.Fprintf(w, "Admin panel")
}

// SAFE: Token comparison using constant-time
import "crypto/subtle"
func verifyToken(token string) bool {
	expected := os.Getenv("AUTH_TOKEN")
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

func main() {
	mux := http.NewServeMux()
	mux.Handle("/admin", requireAuthMiddleware(http.HandlerFunc(adminHandler)))

	client := secureClient()
	resp, _ := client.Get("https://api.example.com/data")
	fmt.Println(resp.Status)
}
