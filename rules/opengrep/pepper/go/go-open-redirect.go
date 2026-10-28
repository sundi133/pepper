package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func login(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	// ruleid: pepper.go.open-redirect
	http.Redirect(w, r, next, http.StatusFound)
	// ok: pepper.go.open-redirect
	http.Redirect(w, r, "/profile/"+next, http.StatusFound)
	// ok: pepper.go.open-redirect
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func checked(w http.ResponseWriter, r *http.Request) {
	next := r.FormValue("next")
	if !isSafeRedirect(next) {
		next = "/"
	}
	// ok: pepper.go.open-redirect
	http.Redirect(w, r, next, http.StatusFound)
}

func ginLogin(c *gin.Context) {
	// ruleid: pepper.go.open-redirect
	c.Redirect(http.StatusFound, c.Query("return_to"))
}
