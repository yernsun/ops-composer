# Authentication and PostgreSQL worker rules

- Auth uses opaque database-backed sessions and explicit Argon2id settings; never place credentials
  or session tokens in logs, model reprs, URLs, or browser storage.
- Every authenticated unsafe operation uses the shared Session + Origin/Referer + session-bound
  double-submit CSRF dependency. Missing security headers are 403 responses, not validation errors.
- Unknown users take the dummy-hash verification path. Successful login upgrades stale hashes.
- Login attempts consume committed PostgreSQL rate-limit buckets before expensive password work;
  do not roll failed-attempt counters back with the authentication transaction.
- Production authentication fails closed unless cookies are Secure and allowed origins are HTTPS.
- Authentication/session responses are not cacheable, and external clients branch on stable error
  codes rather than server message text.
- Correlate HTTP diagnostics with `X-Request-ID`; structured logs and config summaries never include
  bodies, credentials, cookies, session/CSRF tokens, database URLs, or secrets.
- The worker claims queued runs with PostgreSQL `FOR UPDATE SKIP LOCKED`, renews its database lease,
  and acquires the unique per-host lock before execution.
- Run events are committed to PostgreSQL before SSE clients can replay them by sequence. Do not add
  an outbox, external broker, pub/sub channel, or separate queue service in M1.
- Recovery changes abandoned running work to `INTERRUPTED`; retry always creates a new immutable Run.
