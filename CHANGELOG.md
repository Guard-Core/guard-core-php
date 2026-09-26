# Release Notes

Unreleased
----------

CORS support
------------

### Added

- **CORS support: the engine now runs the reference `CorsHandler` and its preflight short-circuit instead of fail-closed rejecting `enableCors`.** Ported from guard_core `handlers/cors_handler.py` with the field defaults of the `cors_*` SecurityConfig fields (`_security_config_fields.py`): `enableCors` plus `corsAllowOrigins` (default `['*']`), `corsAllowMethods` (default `GET, POST, PUT, PATCH, DELETE, OPTIONS`, uppercased at construction, an empty list falling back to `['GET']` like the reference `or` default), `corsAllowHeaders` (default `['*']`, lowercased), `corsAllowCredentials`, `corsExposeHeaders`, and `corsMaxAge` (default `600`, a configured `0` falling back like `config.cors_max_age or 600`). The wildcard-origin plus credentials misconfiguration fails config construction with the reference message (`CORS misconfiguration: wildcard origin '*' is incompatible with cors_allow_credentials=True`), and `with()` re-validates the copy. Dispatch mirrors the adapter contract (fastapi-guard `guard/middleware.py` `_handle_preflight` / `_inject_cors_headers`), structurally following guard-core-go #24: a preflight (OPTIONS carrying `Access-Control-Request-Method`) executes the security pipeline first and is then short-circuited with `200 OK` or `400 Disallowed CORS: origin, method, headers` (the verdict headers are attached before the failure decision, so the 400 still carries allow-methods/max-age/credentials), and every blocked response the engine returns composes the CORS verdict headers on top of the engine's blocked-response set. A disallowed origin on a normal request simply gets no CORS headers (the browser enforces), and no-origin requests are untouched; the fail-secure unresolvable-client response composes the CORS headers like any other blocked response. For pass-through responses the new `GuardEngine::corsResponseHeaders($request)` hands adapters the per-request CORS map (Vary, Allow-Origin echoing the request origin or `*`, Allow-Credentials, Expose-Headers) to merge with their outgoing headers, mirroring `_inject_cors_headers`. With CORS disabled the policy is null and the engine behaves exactly as before. Coverage lives in the new `bin/test_cors.php` honesty runner (67 assertions: allowed/wildcard/disallowed/combined preflights, the allow-headers wildcard echo, credentials, banned-IP preflights and ordinary blocked responses composing the CORS headers, the `corsResponseHeaders` pass-through API, disabled-behavior pins, config normalization, the `or` fallbacks, and `with()` immutability) registered in the Makefile `RUNNERS` list and the CI workflow. Divergence note: the Go engine composes the CORS headers on top of its security-header set; the PHP engine has no engine-side security-header block yet (a documented gap), so blocked responses here carry only the body `Content-Type` plus the CORS headers.

### Verification

- Full suite green on PHP 8.3 (Docker, php:8.3-cli + throwaway redis:7-alpine, no host php/composer), mirroring the CI workflow step for step: `composer install`, the `php -l` sweep (LINT_OK), `composer validate --strict`, and all `bin/` runners including `bin/conformance.php` 184/184 (verdicts unchanged), `bin/test_state.php`, `bin/test_ratelimit.php` 95/95, `bin/test_geo_rate_limits.php` 97/97, `bin/test_pipeline.php` 93/93, `bin/test_m3b.php` 99/99, `bin/test_m4.php` 132/132 (CORS fail-closed pin removed), `bin/test_m3c.php` 93/93, `bin/test_nfkc.php` 142301/142301, `bin/test_binary_noise_gate.php` 80/80, `bin/test_recon_context_gate.php` 141/141, `bin/test_recon_raw_view_scan.php` 77/77, `bin/test_body_form_scan.php` 72/72, `bin/test_json_walk.php` 64/64, `bin/test_exempt_ips.php` 52/52, `bin/test_excluded_headers.php` 50/50, `bin/test_large_body.php` 24/24, and the new `bin/test_cors.php` 67/67.

v4.1.0 (2026-09-26)
-------------------

Excluded detection headers config
---------------------------------

### Added

- **The reference's excluded-header detection surface is now available in PHP: the hardcoded proxy identity set (`HeaderExclusions::DEFAULT_EXCLUDED_HEADERS`, the reference's `_DEFAULT_EXCLUDED_HEADERS`) plus a new `SecurityConfig` field (`excludedDetectionHeaders`, spec-frozen name `excluded_detection_headers`), and excluded headers are no longer absent from the scan.** Before this change PHP had no header exclusion surface at all, so a bare `x-forwarded-for: 192.168.65.1` false-positived the ssrf category, and the only way to silence a noisy header was to disable detection entirely. The header scan in `SuspiciousActivityCheck::scanValues` now resolves the merged exclusion set (defaults plus the configured entries, lowercased on merge, entries kept verbatim like every sibling exclusion field) through the new `RenzoFranceschini\GuardCore\Detection\HeaderExclusions` port of `guard_core/_utils/detection_config.py`, and an excluded header keeps scanning with every enabled category except the ssrf skip resolved per value (`_excluded_header_skip_categories`): address-carrying headers (`host`, `origin`, the forwarding family, the client-ip family, `via`) skip ssrf for any value, any other excluded header skips ssrf only when its whole value parses as an address chain (`_strip_forwarded_entry_port` plus comma-token IP parsing, so `10.0.0.5, 172.16.0.1` reads as a proxy chain while `203.0.113.10' OR '1'='1` still detects as sqli and `<script>alert(1)</script>` as xss, and the always-scan cmd_injection shapes such as `${jndi:...}` keep detecting everywhere). The skip set rides on the scan entries (embedded-JSON walk leaves included) and is filtered in `check()` next to the `enabled_detection_categories` filter. Entries are validated fail-closed at construction exactly like `excluded_detection_params`/`excluded_detection_body_fields` (`validateExclusionSet`), and the field participates in `with()` immutability and revision bumping like sibling fields. Parity with guard-core `excluded_detection_headers`.

### Verification

- Full suite green on PHP 8.3 (Docker, php:8.3-cli, throwaway redis:7-alpine for the Redis-backed runners): `bin/conformance.php` 184/184 (verdicts unchanged), `bin/test_nfkc.php` 142301/142301, `bin/test_body_form_scan.php` 72/72, `bin/test_json_walk.php` 56/56, `bin/test_exempt_ips.php` 52/52, `bin/test_state.php`, `bin/test_m3c.php` 93/93, `bin/test_binary_noise_gate.php` 80/80, `bin/test_recon_context_gate.php` 141/141, `bin/test_recon_raw_view_scan.php` 77/77, `bin/test_m3b.php` 106/106, `bin/test_m4.php` 144/144 all green, and the new `bin/test_excluded_headers.php` honesty runner (50 assertions: address-carrying proxy values not flagged by default, structured proxy header values not flagged, jndi/sqli/xss on excluded headers still blocking, unknown headers keeping the full scan, configured exclusions suppressing ssrf only with address chains and ports, the ssrf-only enabled-categories interaction, the `HeaderExclusions` helper matrix, validation and `with()` immutability, and empty-config current-behavior pins) registered in the Makefile `RUNNERS` list and the CI workflow.

Geo rate limit tiers reachable end to end
-----------------------------------------

### Added

- **The `@geo_rate_limit` decorator surface is now available in PHP and the geo rate-limit tier is reachable end to end: `RouteConfig` carries a new `geoRateLimits` map (country code, e.g. `"DE"`, or the `"*"` fallback, each mapped to `{limit, window}`), `RateLimitCheck` threads it into the rate-limit request, and the handler's geo tier resolves the request's country through a resolver callable and enforces the tier at its crossing (country-specific entry first, `"*"` fallback, no match means no geo tier and the default limit applies; the geo tier shares the route's hashed bucket, so endpoint, route, geo and global tiers keep their short-circuit order).** The tier existed in `RateLimitHandler` but nothing reached it: no route config field, no check plumbing. Resolution is gated on a country resolver (`Closure(string): string`, client ip to country code, empty string when unknown) configured on the rate limit handler, wired either as the handler constructor's fifth argument or after engine construction via the new `RateLimitHandler::setGeoResolver()` (adapters reach it through `rateLimitHandler()`); **the resolver is a required part of the feature: with no resolver configured the geo tier is fully inert and the default limit applies** (previously a lone `"*"` entry fired even without a resolver; that divergence from the reference engines is now closed: Python's `_check_geo_rate_limit` returns early when `geo_ip_handler` is missing and Go's `tiersFor` skips the geo tier when `countryOfIP` is nil). Entries are validated with decorator-time leniency mirroring the other `RouteConfig` maps (malformed entries, non-int limit/window, or values below 1 are silently dropped, keys kept verbatim with no case normalization, matching Python and Go), the field participates in `with()` immutability and revision bumping like sibling fields, and `appliesTo` schedules the check for route registries carrying a rate-limit or geo map (mirroring Python's `_route_rate_limit_configured`; the no-registry drop with the feature flag off and the handler's `enable_rate_limiting` gate are pre-existing PHP gating and are kept, so behavior is unchanged when the flag is off). This does not unblock geo country blocking (`blocked_countries`/`whitelist_countries` stay hard-rejected in `SecurityConfig`); the resolver is an injection point for adapters (for example an ipinfo-backed closure), not a geo-IP dependency. Parity with guard-core `geo_rate_limit` (decorators/rate_limiting.py) and guard-core-go `RouteRateConfig.GeoRateLimits` + `tiersFor`.

### Verification

- Full suite green on PHP 8.3 (Docker, php:8.3-cli + throwaway redis:7-alpine, no host php/composer): all `bin/` runners including `bin/conformance.php` (verdicts unchanged), the geo sections of `bin/test_ratelimit.php` updated to the resolver-gated semantics plus a no-resolver inertness pin (unit and wire level), and the new `bin/test_geo_rate_limits.php` honesty runner (unit, pipeline and `--integration` over a real Redis wire) covering: the `RouteConfig` surface (defaults, verbatim roundtrip, all malformed-entry leniency drops, `with()` immutability/revision/carry and the snake_case name rejection), handler tier resolution (DE tier enforced at its crossing with the geo window in `Retry-After`, unknown country and empty-string resolver answers falling back to `"*"`, country-specific entry beating `"*"`, no matching entry leaving the crossing on the global tier, the resolver receiving exactly the client ip and never being called without a geo map, no resolver leaving the tier inert while the same handler wired via `setGeoResolver()` blocks, and `setGeoResolver(null)` unwiring), pipeline end to end (429 at the geo crossing with the `geo tier` reason on `on_block`, the same route staying on the `global tier` reason without a resolver, exempt and whitelist skips preceding the geo tier, the `rate_limit` route bypass skipping it, and passive mode logging without blocking or firing the event), `appliesTo` scheduling, and the wire-level integration (DE crossing over EVALSHA with the hashed bucket, `"*"` fallback over the wire, and no resolver writing no geo bucket at all), registered in the Makefile `REDIS_RUNNERS` list and the CI workflow.

Clean-parse fall-through for nested JSON leaf walks
---------------------------------------------------

### Fixed

- **A payload confined to the structural text of a nested JSON leaf one nesting level down was invisible: a string leaf that itself parses as JSON walked its nested entries but dropped the raw leaf string from the scan.** `JsonWalk::walkEntries` replaced the leaf with its re-parsed walk whenever the nested parse succeeded, so text that only exists in the raw leaf (a duplicate-key remnant the parse collapses, characters living in the JSON structure itself) never reached the pattern scan when every walked leaf looked innocent. The nested walk now falls through to the raw leaf string scanned with the walk context (not the nested suffix), exactly like the reference's `_check_embedded_json` + `_check_value_enhanced` order (the embedded-JSON walk short-circuits the raw scan only when a leaf hits) and the Go engine's guard-core-go #17. The field-level fall-through kept in #18 is untouched; the top-level JSON body walk still never re-parses leaf strings.

### Verification

- Full suite green on PHP 8.3 (Docker, php:8.3-cli, throwaway redis:7-alpine): `bin/conformance.php` 184/184 (verdicts unchanged), `bin/test_nfkc.php` 142301/142301, `bin/test_json_walk.php` 64/64 with 8 new assertions, `bin/test_body_form_scan.php` 72/72, `bin/test_m3c.php` 93/93, `bin/test_state.php`, `bin/test_binary_noise_gate.php` 80/80, `bin/test_recon_context_gate.php` 141/141, `bin/test_recon_raw_view_scan.php` 77/77, `bin/test_exempt_ips.php` 52/52, and the Redis-backed `bin/test_pipeline.php` 107/107, `bin/test_m3b.php` 106/106, `bin/test_m4.php` 144/144. The new walk-level assertions verify red on master (62/64 without the fix) and the runner adds end-to-end pins for a duplicate-key remnant confined to a nested leaf through the form, multipart and header paths.
test_large_body corpus glob refresh
-----------------------------------

### Fixed

- **`bin/test_large_body.php` globbed the retired `tests/Conformance/guard-core-spec-4.0.2` corpus directory, so the runner aborted on master with its corpus invariant reading zero cases.** The glob now points at the live `guard-core-spec-4.0.3` corpus, and the gate invariant is stated against the corpus the engine actually ships: every text-protocol case file (max content 14,725 bytes in `boundaries.json`) stays below `SusPatterns::GATED_PATTERN_MAX_SUBJECT_BYTES` (15,360), so no text verdict in the suite depends on the PCRE2-JIT-gated line-walk family, while `binary_bodies.json` intentionally carries subjects above the gate (max 221,630 bytes) - those cases ride the binary-noise island path, are tracked by a separate assertion, and have their exact verdicts pinned by `bin/conformance.php` (184/184). The runner's own synthetic gate probes (24/24) are unchanged and stay deterministic under both `pcre.jit` settings.

### Verification

- `bin/test_large_body.php` 24/24 green on PHP 8.3 (Docker, php:8.3-cli) against the `guard-core-spec-4.0.3` corpus, red on master before the fix (the corpus invariant failed with zero cases globbed); registered in the Makefile `RUNNERS` list and the CI workflow mirroring the #20 runner-registration pattern.

exempt_ips skip-list for trusted automated clients
---------------------------------------------------

### Added

- **The reference's `exempt_ips` skip-list is now available in PHP: a new `SecurityConfig` field (`exemptIps`, spec-frozen name `exempt_ips`) listing IPs and CIDRs whose requests skip the rate-limit, user-agent and per-route cloud-provider checks.** A non-empty `whitelist` is also an allowlist, so there was no way to let a few known-friendly automated clients (monitoring probes, VPN egress, a partner's server) skip throttling without denying everyone else. An exempt match sets `RequestState::$isExempt` in the global IP stage (the family-local equivalent of the reference's `is_exempt`), and the whitelist deny path is untouched: exemption never adds or removes a deny path and is resolved only after the deny checks pass (mirroring the reference's `_resolve_is_exempt` gating on `is_allowed`), so an exempt IP does not pass a restrictive whitelist it is not on and an IP in both lists is simply a whitelist match. Deliberately still applying to exempt IPs: the blacklist, dynamic IP bans, the global `block_cloud_providers` list (the reference enforces it inside the global IP stage ahead of the flag, so the PHP cloud check resolves the global list directly for exempt requests while route-driven cloud blocks skip) and penetration detection including its violation counting and auto-ban contribution (`SuspiciousActivityCheck` honors only `isWhitelisted`, exactly like the reference). Entries are validated fail-closed at construction exactly like `whitelist`/`blacklist` (IP or CIDR, IPv4, IPv6 and IPv4-matched forms canonicalized the same way; invalid entry throws), and the field participates in `with()` immutability and revision bumping like sibling fields. Parity with guard-core `feat(config): exempt_ips`, upstream PR #118.

### Verification

- Full suite green on PHP 8.3 (Docker, php:8.3-cli, no host php/composer): all `bin/` runners including `bin/conformance.php` (184/184 vectors, verdicts unchanged), and the new `bin/test_exempt_ips.php` honesty runner porting the spec's 10-item acceptance checklist expressible at engine level (52 assertions: exempt exact IP and exempt CIDR exceeding `rate_limit` with normal responses, a non-exempt client still hitting 429 at the limit, empty-whitelist no-deny-path-leak plus the unchanged restrictive-whitelist deny and the both-lists whitelist-match pin, blacklist and dynamic-ban overrides with the flag provably unset, attack payloads from exempt IPs still detected at 400 with the flag set, invalid-entry fail-closed construction, IPv4-mapped and IPv6-CIDR matching with whitelist-matcher parity pins, the user-agent and global-cloud-block consumer checks, and the per-route cloud-block skip) registered in the Makefile `RUNNERS` list and the CI workflow. Spec checklist item 7 (per-route `require_ip`/`block_ip`) is documented as not applicable at engine level: the PHP `RouteConfig` surface has no route-level IP rule lists, so the runner pins the engine-level analog instead (a route bypassing the global IP stage leaves the skip flags unset and rate limiting still applies there).

Excluded detection fields config
--------------------------------

### Added

- **The reference's excluded-field config surface is now available in PHP: `excluded_detection_params` and `excluded_detection_body_fields` on `SecurityConfig`.** `excluded_detection_params` skips a query parameter's whole pair from penetration detection (`key.lower() in excluded_params` in `_scan_query_params`), and `excluded_detection_body_fields` skips urlencoded form pairs and multipart parts by field name and whole JSON subtrees by key at any nesting depth (the body walk and the embedded-JSON walks of query and header values all honor it, mirroring the reference threading `excluded_body_fields` through `_scan_form_body`, `_scan_multipart_part`, `JsonWalk`, `_scan_query_param_value`, and `_scan_normal_header_component`). Entries are kept verbatim (Python's `_STR_SET_ADAPTER` stores them as given) while scanned names and keys are lowercased before the membership test, so the reference's exact case semantics hold (`['SEARCH']` does not suppress a `search` key, `['search']` suppresses `SEARCH`). Empty config keeps current behavior; the fields participate in `with()` immutability and revision bumping like sibling fields.

### Verification

- Full suite green on PHP 8.3 (Docker, throwaway redis:7-alpine): all `bin/` runners including `bin/conformance.php` (184/184 vectors, verdicts unchanged), with 24 new honesty assertions in `bin/test_body_form_scan.php` (query pair skip, body vs query exclusion distinction, JSON key subtree skip at the top level and nested, sibling keys still scanning, array recursion, form pair skip with siblings intact, multipart text and file part suppression, unnamed parts never suppressed, unparseable multipart blob fallback, the raw-value defense-in-depth scan surviving an all-keys-excluded query JSON, verbatim-entry case semantics, empty-config behavior, validation, and `with()` immutability) and 8 in `bin/test_json_walk.php` (subtree skip, exclusion checked before the mongo-operator registry, threading into re-parsed leaf walks, key lowercasing against verbatim entries).

Ordered JSON walk for bodies and embedded JSON values
-----------------------------------------------------

### Added

- **JSON-content-type request bodies now walk as ordered JSON instead of scanning as one raw blob, and query parameters, headers, and form or multipart field values that themselves parse as JSON walk leaf-first with the `:embedded_json` context suffix.** The walk mirrors the reference engine's `body_json_scan.py`/`embedded_json_scan.py` (and the Go engine's `jsonwalk.go`): insertion-ordered parse with duplicate keys keeping the first position and the last value, every object key scanned as a plain `request_body` component, mongo operator keys (`$where`, `$ne`, `$gt`, ...) reported straight from the walk as nosql hits without a pattern scan, scalar leaves scanned as `str(value)` with the plain `request_body` context on the body walk and `<original context>:embedded_json` for embedded values, string leaves that themselves parse as JSON walked again with another suffix, and objects or arrays at the depth cap (32) serialized back to compact JSON and scanned as one value. Malformed input, trailing data, scalar roots, and nesting past the decoder cap fall back to the raw blob or raw value scan. New `JsonWalk` detection class; `SuspiciousActivityCheck` consumes the forced nosql category filtered by `enabled_detection_categories`.

### Verification

- Full suite green on PHP 8.3 (Docker): the thirteen `bin/` runners plus `bin/conformance.php` (184/184 vectors, verdicts unchanged), and the new `bin/test_json_walk.php` honesty runner (48/48: parse gate, insertion order and duplicate keys, scalar renderings, mongo operator hits, depth-cap compact serialization and escaping, pipeline detection through bodies/query/headers, malformed and scalar JSON blob fallback, and recursive embedded walks), verified red on master (the runner aborts on the missing `JsonWalk` class).

Raw-view recon scan
-------------------

### Fixed

- **Backslash-prefixed recon probes such as `\default` were invisible in every configured pipeline.** The preprocessor folds LDAP hex escapes (`\de` -> `Þ`) before the pattern tables run, so a query or body value like `\default` arrived at the recon rows as `Þfault` and matched nothing, and the recon-category rows were excluded from the raw-view pattern set, so the original value was never scanned against them either. The recon rows are now additionally scanned against the signal-preserving raw view (new `PatternData::RECON_RAW_VIEW_PATTERN_SOURCES`, emitted by `tools/gen_tables.py` from the reference table; view exclusion treats them as members of both the processed scans and the raw view), the #116 leading-separator gate applies to raw-view matches unchanged (bare words stay innocent in query and body contexts, separator-prefixed probes detect again, url_path and unknown are unchanged), and a (pattern, match text) deduplication on the raw-view merge keeps a row matching both views a single threat instead of doubling the threat score, with raw-view timeout sources deduplicated the same way (parity with guard-core `fix/raw-view-recon-scan`, upstream commit 81cf07f1; mirrors the Rust engine port in guard-core-rs). This resolves the `\default` divergence pinned by `bin/test_recon_context_gate.php`, which now asserts the probe as a member of `PROBE_PATHS`.

### Verification

- Full suite green on PHP 8.3 (Docker): the eight `bin/` runners plus `bin/conformance.php` (184/184 vectors, verdicts unchanged), the new `bin/test_recon_raw_view_scan.php` honesty runner (77/77: probes detect in query_param/request_body/url_path through the configured `SuspiciousActivityCheck` pipeline, bare words stay innocent, double-view matches collapse to one, `\2fdefault` keeps single-hit decoded semantics), and `bin/test_recon_context_gate.php` at 141/141 with `\default` and `\report.asp` promoted from known divergence to probe.

Form and multipart body scanning with binary islands
----------------------------------------------------

### Added

- **The suspicious-activity scan now extracts request bodies instead of scanning them as one raw value.** Urlencoded bodies scan as field pairs (the field name as a plain `request_body` component, each value with the `request_body:form_field` context), multipart bodies parse per RFC 2046 with the reference engine's observable semantics and scan as part entries (field label plus filename, part headers, payload, each with the `request_body:multipart_field context`), and a body that declares a boundary but carries none falls back to the raw blob scan. Values that parse as embedded JSON scan leaf-first with the `:embedded_json` context suffix, so the per-context gates in the pattern builder see the context of the value actually being scanned for the first time (the suffix was consumed but never produced before).
- **Binary-dense multipart file-part payloads reduce to printable runs before pattern scanning.** A named file part whose binary artifact characters fill at least a fifth of it is reduced to printable runs of at least `detection_binary_min_run_length` (new `SecurityConfig` field, default 16, bounds [4, 1024]) scanned as individual values, so compressed or encrypted upload bytes stop producing attack-shaped matches whose rate grows with file size, while text genuinely embedded in an upload still scans in full; text uploads, short or mostly-text payloads, and whole-body fallback scans keep their full scan. New `BinaryIslands` and `BodyFormScan` detection classes mirror the reference `detection_engine/binary_islands.py` and `_utils/body_form_scan.py` (upstream commit 5f399234); the multipart parser was validated differentially against the reference engine's email parser on 481 hand-built and randomized bodies with identical parts, contexts and islands.

### Verification

- Full suite green on PHP 8.3 (Docker): the eight `bin/` runners plus `bin/conformance.php` (184/184 vectors, verdicts unchanged), and the new `bin/test_body_form_scan.php` honesty runner (41/41: island unit shapes, config bounds, form-field sqli, multipart text/binary smuggling/noise cases, the min-run-length knob, embedded JSON leaves, name and filename scanning, and exact extraction contexts), verified red on master (the runner aborts on the missing extraction classes).

Text/plain block responses, console-safe log lines, and the recon leading-separator gate
-----------------------------------------------------------------------------------------

### Fixed

- **Blocked and error responses went out with no Content-Type.** `GuardResponseFactory::createResponse` built responses with an empty header bag while the security headers carry `X-Content-Type-Options: nosniff`, so every block and error response the adapters copy verbatim (403, 400, 429, the fail-secure 500, custom error messages) went out with no Content-Type at all. Body responses now declare `text/plain; charset=utf-8`; redirects carry no body and stay header-minimal (parity with fastapi-guard #144, upstream commit 4059fbe).
- **Log lines could carry raw control and non-ASCII bytes.** `LogActivity::buildMessage` interpolated redacted-but-unsanitized header, url, reason and trigger values, making line emission depend on the console encoding. Every assembled line is now pure printable ASCII (new `LogSanitizer`, port of the Python `_sanitize_for_log`): newline, carriage return and tab use the short escapes, every other control or non-ASCII code point becomes `\uXXXX`, and raw non-UTF-8 bytes (the surrogate-escape class of the Python engine) become `\xNN` (guard-core 4.0.4 parity, upstream commit f5d53ca5).
- **Deep-nested JSON in loggable values produced raw or half-redacted output.** When the JSON display-redaction depth cap trips (parse failure at the cap or traversal past it), the whole value now collapses to `[REDACTED]` instead of falling through to XML/pair redaction of the raw text; malformed JSON keeps falling through to those fallbacks (guard-core 4.0.4 parity, upstream commit 8bae9459).
- **Recon path rows flagged bare field values such as `?system=SAP` or `?file=README.md`.** Whole-value recon rows whose leading path separator is optional now require the scanned value to live in a path-like context (`url_path` or `unknown`) or to start with a path separator: `/default.asp` style probes still detect in every context, `url_path` behavior is unchanged, and the gate is keyed on the normalized context of the value actually being scanned (parity with guard-core PR #116, upstream commit 79818055). Regenerating the frozen conformance corpus at the post-#116 engine commit is a follow-up.

### Verification

- Full suite green on PHP 8.3 (Docker): the eight `bin/` runners plus `bin/conformance.php` (184/184 vectors, verdicts unchanged), the new `bin/test_recon_context_gate.php` honesty runner (130/130), and the binary-noise gate runner (80/80).

___

v4.0.4 (2026-09-24)
-------------------

First stable release, full parity with guard-core 4.0.4 (v4.0.4)
----------------------------------------------------------------

### Added

- **Full parity with the Python guard-core 4.0.4 engine: all 17 security checks ported and passing.** The behavioral WAF engine now matches the reference engine check-for-check (route config, emergency mode, HTTPS enforcement, request logging, request size and content, required headers, authentication, referrer, custom validators, time window, cloud IP refresh, IP security, cloud provider, user agent, rate limit, suspicious activity, custom request).
- **Binary-noise gates over the detection engine, including the SQLi comment-terminator binary gate.** Noise-prone pattern matches inside binary body content are discarded before reporting, and SQLi patterns that terminate on comment-like byte sequences are explicitly gated in binary bodies, closing the last detection divergence against the reference corpus.
- **Conformance corpus harmonized to spec 4.0.3.** The fixture corpus (`tests/Conformance/`) carries the reference engine's expected values, including binary-body vectors, and must never be hand-edited.

### Changed

- **First stable release on Packagist.** The package installs as `rennf93/guard-core-php` (PHP 8.2+, platform-only dependencies: pcre, mbstring, json); the version is derived from the git tag, and this v4.0.4 tag is the first stable, non-pre-release publish. The earlier v0.1.0 tag was a burned pre-release snapshot and is superseded by this release.

### Verification

- Interop harness against the reference engine: 82/82 vectors passing.
- Full suite: the eight `bin/` runners plus `bin/conformance.php` across PHP 8.2, 8.3 and 8.4 (CI and the Release Gate workflow at the tag).

___
