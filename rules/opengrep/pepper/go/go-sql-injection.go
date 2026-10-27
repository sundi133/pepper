package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: pepper.go.sql-injection
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
	// ruleid: pepper.go.sql-injection
	db.Exec(fmt.Sprintf("DELETE FROM t WHERE id = %s", r.FormValue("id")))
	// ruleid: pepper.go.sql-injection
	db.QueryRowContext(r.Context(), "SELECT 1 FROM t WHERE x = '"+name+"'")

	// ok: pepper.go.sql-injection
	db.Query("SELECT * FROM users WHERE name = $1", name)
	id, _ := strconv.Atoi(r.FormValue("id"))
	// ok: pepper.go.sql-injection
	db.Exec(fmt.Sprintf("DELETE FROM t WHERE id = %d", id))
	// ruleid: pepper.go.sql-injection
	sqlxDB.Get(&u, "SELECT * FROM users WHERE email = '"+r.FormValue("e")+"'")
	// ok: pepper.go.sql-injection
	sqlxDB.Get(&u, "SELECT * FROM users WHERE email = $1", r.FormValue("e"))
	stmt, _ := db.Prepare("SELECT * FROM users WHERE name = $1")
	// ok: pepper.go.sql-injection
	stmt.Query(name)
}

type Filter struct{ Sort string }

func list(c *gin.Context) {
	var f Filter
	c.ShouldBindJSON(&f)
	// ruleid: pepper.go.sql-injection
	gormDB.Raw("SELECT * FROM items ORDER BY " + f.Sort).Scan(nil)
	// ruleid: pepper.go.sql-injection
	gormDB.Where("name = '" + c.Query("n") + "'").Find(nil)
	// ok: pepper.go.sql-injection
	gormDB.Where("name = ?", c.Query("n")).Find(nil)
}
