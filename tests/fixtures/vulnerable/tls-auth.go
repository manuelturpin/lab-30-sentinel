// VULNERABLE: TLS/Certificate and Authentication Issues
// CWE-295 (Improper Cert Validation), CWE-287 (Improper Authentication)

package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

// CWE-295: TLS certificate verification disabled
func insecureClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return &http.Client{Transport: transport}
}

// CWE-295: Minimum TLS version too low
func weakTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS10,
	}
}

// CWE-295: No certificate verification callback
func customVerify() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return nil // Always accept
		},
	}
}

// CWE-287: Missing authentication middleware
func adminHandler(w http.ResponseWriter, r *http.Request) {
	// No auth check before sensitive operation
	deleteUser(r.FormValue("user_id"))
	fmt.Fprintf(w, "User deleted")
}

// CWE-287: Weak token comparison
func verifyToken(token string) bool {
	// Timing-safe comparison not used
	return token == "hardcoded-admin-token-12345"
}

func main() {
	client := insecureClient()
	resp, _ := client.Get("https://api.example.com/data")
	fmt.Println(resp.Status)
}
