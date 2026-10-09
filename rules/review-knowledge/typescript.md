## JavaScript / TypeScript security review guide
**Sources:** Express/Koa/Nest/Next `req.body/query/params/headers/cookies`, `request.formData()`, `URL.searchParams`, route `params`, server actions arguments, WebSocket/SSE messages, `postMessage` data, `location`/`document.referrer`.
**Sinks:** `db.query/exec` built by concatenation or template strings, Prisma `$queryRawUnsafe`/`$executeRawUnsafe`, Sequelize `literal`, Mongo `$where`/operator injection from raw objects; `child_process.exec/execSync`, `spawn` with `shell:true`; `eval`, `new Function`, `vm.runIn*`; `fs.*` with input paths; `res.redirect`, `res.render` / raw EJS `<%- %>`; `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `dangerouslySetInnerHTML`, `v-html`; `new RegExp(input)`; `fetch/axios` to user URLs (SSRF); `Object.assign`/spread/`lodash.merge` of request bodies (prototype pollution, mass assignment); `jwt.decode` used as verification.
**Guards:** parameterised `$1`/`?`, ORM bindings, Prisma `$queryRaw` tagged template, zod/joi/class-validator with whitelist, helmet, csurf/SameSite, `path.basename` + allowlist, DOMPurify, Nest `@UseGuards`, Next middleware matchers.

**Review checklist**
- Missing `await` on an async auth/permission check (`if (checkAccess(user))` with a Promise is always truthy) → auth bypass.
- `==` coercion in token/role/amount comparisons; `parseInt` without radix or NaN handling on amounts.
- Unhandled promise rejections in request paths; empty `catch` that continues after a failed security check.
- Nest: controllers/handlers lacking `@UseGuards` that siblings have; `ValidationPipe` without `whitelist/forbidNonWhitelisted` → mass assignment.
- Next.js: server actions and route handlers are public endpoints — each needs its own auth; middleware `matcher` gaps; secrets in `NEXT_PUBLIC_*`.
- React: user HTML through `dangerouslySetInnerHTML`, `href={userUrl}` allowing `javascript:`; tokens in `localStorage`.
- CORS `origin: true`/reflecting origin with `credentials: true`.
- File upload (multer/busboy/formidable) without extension/MIME allowlist, size limit, filename sanitisation.
- Cookies for sessions lacking `httpOnly`, `secure`, `sameSite`.
