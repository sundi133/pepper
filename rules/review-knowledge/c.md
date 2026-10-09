## C / C++ / Objective-C security review guide
**Sources:** `recv/read/fread/fgets`, `argv`, `getenv`, network packets, file formats being parsed, IPC/FFI boundaries, JNI.
**Sinks:** `strcpy/strcat/sprintf/vsprintf/gets/scanf("%s")`, `memcpy/memmove` with attacker-influenced length, array indexing with untrusted index, `printf(input)` (format string), `system/popen/exec*`, `alloca` with untrusted size, `malloc(n * size)` without overflow check.
**Guards:** `snprintf`/`strlcpy` with correct bounds, explicit length validation before copy, checked multiplication for allocation sizes, constant-bounded loops, RAII/smart pointers.

**Review checklist**
- Buffer overflow/underflow and off-by-one in parsers (CWE-120/125/787); integer overflow in size calculations (CWE-190) leading to small allocations.
- Use-after-free, double free, dangling references/iterators after container mutation (CWE-416/415).
- Unchecked `malloc`/`new` failure; NULL dereference on error paths.
- Signed/unsigned confusion in length checks (`int len` compared to `size_t`).
- TOCTOU on files (`access` then `open`), unsafe temp files.
- Data races on shared state between threads without locks/atomics.
- C++: missing RAII for locks/handles, violated Rule of 0/3/5 causing double free, exception paths leaking or leaving state half-updated.
