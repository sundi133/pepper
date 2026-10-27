package main

import (
	"crypto/tls"
	"net/http"
)

func client() *http.Client {
	tr := &http.Transport{
		// ruleid: pepper.go.tls-insecure-skip-verify
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cfg := &tls.Config{}
	// ruleid: pepper.go.tls-insecure-skip-verify
	cfg.InsecureSkipVerify = true
	// ok: pepper.go.tls-insecure-skip-verify
	pinned := &tls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: verifyPinned}
	// ok: pepper.go.tls-insecure-skip-verify
	strict := &tls.Config{MinVersion: tls.VersionTLS12}
	_, _ = pinned, strict
	return &http.Client{Transport: tr}
}
