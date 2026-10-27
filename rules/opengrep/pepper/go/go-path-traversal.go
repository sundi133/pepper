package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

const base = "/srv/files"

func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	// ruleid: pepper.go.path-traversal
	data, _ := os.ReadFile(filepath.Join(base, name))
	// ruleid: pepper.go.path-traversal
	http.ServeFile(w, r, base+"/"+name)
	// ruleid: pepper.go.path-traversal
	os.Remove(r.FormValue("path"))

	// ok: pepper.go.path-traversal
	os.ReadFile(filepath.Join(base, filepath.Base(name)))
	// ok: pepper.go.path-traversal
	os.ReadFile(filepath.Join(base, filepath.Clean("/"+name)))
	w.Write(data)
}

func view(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(base, r.URL.Query().Get("f"))
	if !strings.HasPrefix(filepath.Clean(p), base+string(os.PathSeparator)) {
		http.Error(w, "forbidden", 403)
		return
	}
	// ok: pepper.go.path-traversal
	os.Open(p)
}

func upload(c *gin.Context) {
	file, _ := c.FormFile("doc")
	// ruleid: pepper.go.path-traversal
	c.SaveUploadedFile(file, base+"/"+file.Filename)
	// ok: pepper.go.path-traversal
	c.SaveUploadedFile(file, filepath.Join(base, filepath.Base(file.Filename)))
	// ruleid: pepper.go.path-traversal
	c.File(base + "/" + c.Param("name"))
}
