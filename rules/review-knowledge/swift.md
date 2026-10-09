## Swift / Kotlin-mobile / Dart security review guide
**Sources:** deep links/universal links, URL schemes, `UIPasteboard`, WebView JavaScript bridges/message handlers, push payloads, network responses, platform channels.
**Sinks:** `WKWebView` `evaluateJavaScript`/`loadHTMLString` with input, JS bridges exposing native functions, `NSKeyedUnarchiver` without secure coding, file paths from input, SQL via string interpolation (SQLite/FMDB/sqflite), `openURL` with user URLs.
**Guards:** `NSSecureCoding`, parameterised SQLite, URL allowlists, Keychain/Keystore for secrets, certificate pinning.

**Review checklist**
- Secrets, tokens or PII in `UserDefaults`/`SharedPreferences`/plain files/logs instead of Keychain/Keystore.
- ATS/cleartext exceptions, disabled TLS validation, missing pinning for payment/auth traffic.
- Deep-link handlers performing privileged actions without auth/confirmation.
- Force unwrap/`try!`/`!` on external data (crash = DoS); data races across actors/isolates; `BuildContext`/state used after `await` without mounted check.
- Client-side only authorization or price calculation trusted by the server.
