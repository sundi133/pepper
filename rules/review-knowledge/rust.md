## Rust security review guide
**Sources:** Actix (`web::Json/Path/Query/Form`, `HttpRequest` headers), Axum (`Json`, `Path`, `Query`, `TypedHeader`), Rocket/Tide/Warp request types, gRPC (tonic) messages, webhook bodies, FFI inputs.
**Sinks:** `std::process::Command` with a shell (`sh -c`) or input-built args; raw SQL via `format!`/concatenation into `sqlx::query`, `diesel::sql_query`, `execute`; `unsafe` blocks using untrusted lengths/offsets (`get_unchecked`, `from_raw_parts`, `ptr::copy`, `transmute`); file paths from input (`std::fs`, `tokio::fs`); outbound `reqwest` to user URLs (SSRF); `serde` into types with `#[serde(flatten)]`/untagged enums that let clients set privileged fields.
**Guards:** sqlx `query!`/bind parameters, diesel DSL, strongly typed serde structs (`serde_json::from_str` into a concrete struct is SAFE typed parsing, NOT CWE-502), `Path::canonicalize` + prefix check, auth extractors/middleware (`FromRequest` impls, `wrap(...)` guards), `secrecy::Secret`, `masking::Secret`/`StrongSecret` wrappers.

**Review checklist**
- Authorization: handlers that accept `merchant_id`/`profile_id`/`org_id`/`customer_id`/resource ids from the request must scope the DB lookup by the authenticated principal. Compare with the auth extractor used by sibling routes; a route registered without the auth wrapper its neighbours use is a missing-auth finding.
- `unsafe`: every block needs a provable invariant; any length, index or pointer derived from input inside `unsafe` is memory corruption (CWE-119/787). Unsafe invariants split across modules are suspect.
- Integer arithmetic on money/amounts: release builds wrap on overflow. Prefer `checked_*`/`saturating_*`; flag `as` casts that truncate (`i64 as i32`, `u64 as usize`) and float math for currency.
- `unwrap()`/`expect()`/indexing `[]` on request-derived data in request paths = attacker-triggered panic (DoS, CWE-248/617).
- Async: holding `std::sync::Mutex`/`RwLock` guard across `.await` (deadlock); blocking I/O (`std::fs`, `thread::sleep`) on the runtime; cancellation-unsafe futures in `select!` that can lose a write or leave a payment half-applied; dropped futures (work never done).
- Error handling: `map_err(|_| ...)`/`.ok()`/`let _ =` that discards an auth, signature or DB error and continues (fail-open); ignored `#[must_use]` results.
- Secrets: logging or `Debug`-printing structs that hold keys/card data without a masking wrapper; `Secret::expose()` into logs/responses.
- Webhooks/callbacks from payment processors: signature verified over the raw body before parsing, constant-time comparison, replay protection.
- Crypto: `rand::thread_rng` is fine; non-crypto RNGs or hard-coded keys/IVs are not. TLS: `danger_accept_invalid_certs(true)`.
