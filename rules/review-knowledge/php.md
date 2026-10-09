## PHP security review guide
**Sources:** `$_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES/$_SERVER`, Laravel `$request->input/all/query/route`, Symfony `Request`.
**Sinks:** `mysqli_query`/`PDO::query` with concatenation, Laravel `DB::raw`/`whereRaw`/`selectRaw` with interpolation; `system/exec/shell_exec/passthru/proc_open/popen`/backticks; `include/require` with variable paths (LFI/RFI); `unserialize` (object injection), `phar://` wrappers; `file_get_contents/fopen/readfile` with input paths or URLs (SSRF); `echo`/`print` of unescaped input, Blade `{!! !!}`; `eval`, `preg_replace` with `/e`, `assert` with strings; `header('Location: ' . $input)`.
**Guards:** PDO prepared statements, Eloquent bindings, `htmlspecialchars` with ENT_QUOTES, Blade `{{ }}`, `basename`/`realpath` + allowlist, `password_hash/password_verify`, Laravel policies/gates/middleware.

**Review checklist**
- Loose comparison (`==`, `in_array`/`array_search` without strict) in auth, token, payment or state logic (type juggling bypass, `"0e123" == "0e456"`).
- `Model::find($id)` without policy/owner scoping (IDOR); `$fillable`/`$guarded = []` mass assignment.
- Passwords with `md5`/`sha1`; `rand`/`mt_rand` for tokens (use `random_bytes`).
- Errors suppressed with `@` or empty catch around security checks.
- File uploads trusting client filename/MIME, stored under web root (webshell).
- Routes outside the `auth` middleware group; CSRF middleware exceptions.
