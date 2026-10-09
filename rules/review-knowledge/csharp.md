## C# / .NET security review guide
**Sources:** `Request.Query/Form/Headers/Cookies/RouteValues`, model-bound action parameters, `[FromBody]` DTOs, SignalR hub method args.
**Sinks:** `SqlCommand` text with concatenation, EF `FromSqlRaw`/`ExecuteSqlRaw` with interpolation; `Process.Start`; `BinaryFormatter`, `NetDataContractSerializer`, `LosFormatter`, Json.NET `TypeNameHandling` != None; `XmlDocument` with `XmlResolver` set (XXE); `Path.Combine` + `File.*` with input; `Html.Raw`; `Redirect(userUrl)` without `Url.IsLocalUrl`; `HttpClient` to user URLs (SSRF).
**Guards:** `SqlParameter`, EF LINQ / `FromSqlInterpolated`, `[Authorize]` with policies, `[ValidateAntiForgeryToken]`, Razor encoding, `Path.GetFullPath` + prefix check.

**Review checklist**
- Controllers/actions with `[AllowAnonymous]` or missing `[Authorize]` that siblings have; resource lookups not scoped to the user (IDOR).
- Over-posting: entities bound directly from request bodies.
- `async void`, `.Result`/`.Wait()` deadlocks; swallowed exceptions around auth/signature checks.
- `Random` for tokens (use `RandomNumberGenerator`); `ServerCertificateCustomValidationCallback = (...) => true`.
- `unchecked` arithmetic on amounts; `decimal` vs `double` for currency.
