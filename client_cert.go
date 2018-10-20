package main

import (
	"crypto/tls"
	"os"
	"strconv"
	"strings"
	"time"
)

// readClientCert - helper function to read client certificate
// from pem formatted certPath and keyPath files
func readClientCert(certPath, keyPath string) ([]tls.Certificate, error) {
	if certPath != "" && keyPath != "" {
		// load keypair
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}

		return []tls.Certificate{cert}, nil
	}
	return nil, nil
}

// generateTLSConfig - helper function to generate a TLS configuration based on
// config
func generateTLSConfig(c config) (*tls.Config, error) {
	certs, err := readClientCert(c.certPath, c.keyPath)
	if err != nil {
		return nil, err
	}
	// Typically the log would go to an open file:
	if c.tlsdebug == true {
		now := time.Now()
		secs := now.Unix()
		filename := strings.Join([]string{"tls-secrets.txt.", strconv.FormatInt(secs, 10)}, "")
		w, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		// w := os.Stdout
		tlsConfig := &tls.Config{
			InsecureSkipVerify: c.insecure,
			Certificates:       certs,
			KeyLogWriter:       w,
		}
		return tlsConfig, err
	}
	// Disable gas warning, because InsecureSkipVerify may be set to true
	// for the purpose of testing
	/* #nosec */
	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.insecure,
		Certificates:       certs,
		// KeyLogWriter:       w,
	}
	return tlsConfig, nil
}
