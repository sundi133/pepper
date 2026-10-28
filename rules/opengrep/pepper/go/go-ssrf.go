package main

import (
	"fmt"
	"net/http"
	"net/url"
)

func proxy(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	// ruleid: pepper.go.ssrf
	resp, _ := http.Get(target)
	// ruleid: pepper.go.ssrf
	req, _ := http.NewRequest("GET", r.FormValue("hook"), nil)
	// ruleid: pepper.go.ssrf
	httpClient.Get(target + "/status")

	// ok: pepper.go.ssrf
	http.Get("https://api.github.com/users/" + target)
	// ok: pepper.go.ssrf
	http.Get(fmt.Sprintf("https://api.example.com/items/%s", url.PathEscape(target)))
	_, _ = resp, req
}
