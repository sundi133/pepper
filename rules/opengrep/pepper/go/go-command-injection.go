package main

import (
	"net/http"
	"os/exec"
)

func run(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// ruleid: pepper.go.command-injection
	exec.Command("sh", "-c", "ping -c 1 "+host).Run()
	// ruleid: pepper.go.command-injection
	exec.Command(r.FormValue("tool"), "--version").Run()
	// ruleid: pepper.go.command-injection
	exec.CommandContext(r.Context(), "bash", "-c", host).Run()

	// ok: pepper.go.command-injection
	exec.Command("ping", "-c", "1", host).Run()
	// ok: pepper.go.command-injection
	exec.Command("sh", "-c", "uptime").Run()
}
