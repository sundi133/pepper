## Ruby / Rails security review guide
**Sources:** `params[]`, `request.headers`, `cookies`, Active Job arguments, webhook bodies.
**Sinks:** `where("...#{params[:x]}")`, `find_by_sql`, `execute`, `order(params[:sort])`, `pluck` with interpolation; `system`/backticks/`exec`/`spawn`/`Open3` with interpolated strings; `eval`/`instance_eval`/`send`/`public_send`/`constantize` with input; `Marshal.load`, `YAML.load` (not `safe_load`); `send_file`/`File.open` with input paths; `raw`/`html_safe`/`<%==`; `redirect_to params[:url]` or `allow_other_host: true`.
**Guards:** hash/array `where` conditions, bind params, strong parameters with explicit `permit`, `sanitize`, ERB autoescape, Pundit/CanCan policies, `protect_from_forgery`.

**Review checklist**
- `Model.find(params[:id])` before ownership/policy scope (IDOR); controllers missing `before_action :authenticate_user!`/`authorize` that siblings have.
- Strong params with `permit!`, `to_unsafe_h`, or permitting `role`/`admin`/`user_id` (mass assignment).
- `skip_before_action :verify_authenticity_token` on browser-authenticated state changes; insecure session cookie flags.
- Broad `rescue` that hides failures or renders `e.message` to users.
- Active Job retries duplicating payments/emails without idempotency keys; external side effects inside transactions; `update_all`/`delete_all` skipping validations that enforce invariants.
- Truthiness assumptions (`0`, `""` are truthy in Ruby) in permission checks.
