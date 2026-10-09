## Java / Kotlin / Spring security review guide
**Sources:** `@RequestParam/@PathVariable/@RequestBody/@RequestHeader`, `HttpServletRequest.getParameter/getHeader`, JAX-RS params, message listeners (Kafka/JMS), Ktor `call.parameters/receive`.
**Sinks:** `Statement.execute/executeQuery` with concatenation, JPA `createQuery`/`createNativeQuery` with concatenation, Spring `JdbcTemplate` with built strings; `Runtime.exec`, `ProcessBuilder`; `ObjectInputStream.readObject`, `XMLDecoder`, Jackson default typing / `@JsonTypeInfo(use = CLASS)`, SnakeYAML `new Yaml().load`; XPath/LDAP built from input; `DocumentBuilderFactory`/`SAXParser` without disallow-doctype (XXE); `Files.*`/`new File` with input paths; SpEL/OGNL/template evaluation of input; `RestTemplate/WebClient` to user URLs (SSRF); reflection/`Class.forName` with input.
**Guards:** `PreparedStatement`, JPA parameters/Criteria, `@PreAuthorize/@Secured`, method security, OWASP Encoder, XML secure processing, path normalisation + allowlist.

**Review checklist**
- Controllers missing `@PreAuthorize` that siblings have; `SecurityFilterChain` `permitAll()` patterns that are broader than intended; CSRF disabled for cookie-auth apps.
- `repository.findById(id)` from request without owner/tenant check (IDOR).
- Entities bound directly from `@RequestBody` (mass assignment of role/owner/status).
- `@Transactional` on private methods or self-invocation (no transaction → partial writes, race on balances); missing optimistic/pessimistic locking for money/inventory.
- `Optional.get()`/NPEs on request data (DoS); broad `catch (Exception e)` that continues after auth/signature failure.
- `CompletableFuture`/`parallelStream` with shared mutable state; `SimpleDateFormat` shared across threads.
- `RestTemplate` without timeouts; `TrustAllCerts`/`NoopHostnameVerifier`.
- Kotlin: `!!` on request data, `lateinit` misuse; coroutine scope leaks.
