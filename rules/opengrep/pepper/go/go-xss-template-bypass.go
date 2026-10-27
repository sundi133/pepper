package main

import (
	"html/template"
	"net/http"

	"github.com/microcosm-cc/bluemonday"
)

func page(w http.ResponseWriter, r *http.Request) {
	bio := r.FormValue("bio")
	// ruleid: pepper.go.xss-template-escaping-bypassed
	data := template.HTML("<p>" + bio + "</p>")
	// ok: pepper.go.xss-template-escaping-bypassed
	safe := template.HTML(bluemonday.UGCPolicy().Sanitize(bio))
	// ok: pepper.go.xss-template-escaping-bypassed
	fixed := template.HTML("<b>static</b>")
	tmpl.Execute(w, map[string]any{"bio": data, "s": safe, "f": fixed, "plain": bio})
}
