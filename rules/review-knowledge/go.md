## Go security review guide
**Sources:** `r.URL.Query()`, `r.FormValue/PostFormValue`, `r.Header.Get`, `json.NewDecoder(r.Body)`, gin `c.Param/Query/PostForm/ShouldBind`, echo/fiber context getters, gRPC request messages.
**Sinks:** `db.Query/Exec` with `fmt.Sprintf`/concat, gorm `Raw`/`Where(string)` with interpolation; `exec.Command("sh","-c",...)` or input-built args; `text/template` for HTML; `os.Open/ReadFile` and `filepath.Join` with input then file IO; `http.Get(userURL)` (SSRF); `http.Redirect` to user URL; slice indexing/`make` with untrusted lengths; `unsafe` pointers.
**Guards:** `$1`/`?` placeholders, gorm struct conditions, `html/template`, `filepath.Clean` + `strings.HasPrefix(base)` check, auth middleware on router groups.

**Review checklist**
- Ignored errors (`v, _ := f()`, unchecked `err`) on auth, signature, DB or crypto calls → fail-open.
- Router groups: handlers registered outside the group that applies auth middleware.
- Lookups by id from the request not scoped by the authenticated user/tenant (IDOR).
- Goroutines without exit/cancellation (leak/DoS); missing `context.Context` propagation and timeouts on outbound calls (`http.Client{}` without Timeout).
- Data races on maps/shared state across goroutines (concurrent map write panic, inconsistent balances); check-then-act without mutex/transaction.
- `defer` in loops holding resources; `%v` instead of `%w` hiding sentinel errors used in security decisions.
- Integer overflow/truncation in conversions (`int64`→`int32`) on sizes and amounts.
- `math/rand` for tokens (use `crypto/rand`); `InsecureSkipVerify: true`.
