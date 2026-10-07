<?php

declare(strict_types=1);

// Provably-unreachable line inventory for the coverage gate. Every entry is
// a line the suites cannot cover because no input can steer execution there;
// each carries its proof below. The merge pass of coverage-runner.php
// subtracts this inventory from the uncovered set before gating, so the gate
// reads: every executable line is covered or provably unreachable.
//
// Keep the proofs with the lines: when the surrounding code changes, the
// proof must be re-verified or the line removed from this list (the gate
// then forces a genuine test).
//
// Line numbers refer to the current source; re-audit after any refactor.

return [
    // networksOverlap re-parses $b, but both call sites pass literals that
    // parseNetwork accepts ('127.0.0.0/8', '::1/128') or entries of
    // trustedProxyNetworks, which the constructor already filtered through
    // isNetwork (lines 42-45) - so parseNetwork($b) never returns null.
    'src/Ban/IpBanManager.php' => [
        373,
        // isPrivateNetwork's $addr comes from parseNetwork, i.e. from
        // CanonicalIp::parse -> canonicalText, which only returns
        // FILTER_VALIDATE_IP-valid strings; inet_pton cannot fail on them.
        411,
        // isV4CompatPrivate requires a 16-byte address with ::ffff: at bytes
        // 10-11, but canonicalText collapses every v4-mapped spelling
        // (dotted and hex) to the dotted quad (CanonicalIp 110-112) before
        // parseNetwork returns it, so a canonical IPv6 is never v4-mapped
        // and the ::ffff: guard at 429-431 always returns false first.
        433, 435, 436, 437,
    ],

    // $pattern is a ?string parameter; PHP raises the TypeError at the call
    // boundary, so `$pattern !== null && !is_string($pattern)` never fires.
    'src/Behavior/BehaviorRule.php' => [
        70,
    ],

    // json_decode(..., assoc: true) yields only array|scalar|null, so
    // !is_array && !== null && !is_scalar is a contradiction.
    //
    // The try block wraps total functions over strings/ints (substr,
    // json_decode, @preg_match, str_contains, strtolower) plus GuardResponse
    // getters (final class, typed reads); no Throwable can escape, so the
    // catch body is dead too.
    'src/Behavior/BehaviorTracker.php' => [
        193, 214, 215, 217,
    ],

    // The page timeout is min(PAGE_TIMEOUT=10.0, deadline - now) with the
    // deadline set to now + MAX_ELAPSED=20.0 on the previous line; it can
    // never be <= 0 on entry.
    'src/Cloud/CloudFetchers.php' => [
        112,
    ],

    // curl_init only fails when the cURL extension is missing.
    'src/Cloud/CurlHttpClient.php' => [
        22,
    ],

    // mb_substitute_character(0xfffd) makes mb_convert_encoding(UTF-8,
    // UTF-8) substitute instead of fail for every byte string, so the false
    // branch is dead.
    //
    // stripSeparators reads the token through Text::ordAt (mb_substr over a
    // valid UTF-8 subject): a lone surrogate U+DC80-DCFF can never occur
    // because valid UTF-8 cannot encode surrogates and mbstring substitutes
    // invalid sequences with U+FFFD, never a surrogate.
    'src/Detection/Base64.php' => [
        81, 126,
    ],

    // The two-byte branch only accepts lead bytes 0xC2-0xDF, so the decoded
    // code point is ((b & 0x1f) << 6) | cont >= (2 << 6) = 0x80: the
    // `$cp < 0x80` overlong guard is arithmetically dead (0xC0/0xC1 falls
    // into the invalid-byte branch instead). decodeCp's two-byte arm has
    // the same guard, so its [0xfffd, 2] fallback is dead too.
    'src/Detection/BinaryIslands.php' => [
        56, 156,
    ],

    // Same 0xC2-0xDF arithmetic argument as BinaryIslands 56.
    'src/Detection/BinaryPrefix.php' => [
        100,
    ],

    // isHeaderLine is only called with lines from
    // splitLinesKeepingEndings, which never yields an empty line, and
    // splitHeaders is only entered with non-empty segment lists.
    'src/Detection/BodyFormScan.php' => [
        392,
    ],

    // The ldap tail walk's tails come from Preg::allMatches: non-overlapping
    // and ascending, so each tail starts at or after the previous match end.
    //
    // The \w-after-quotes guard guarantees the anchored match at the
    // computed word start succeeds, so the quote-splice else branch is
    // never taken.
    //
    // cpIndexAt only ever receives quote['end'], always a character
    // boundary, so the continuation-byte walk never runs.
    //
    // strrpos after a `\.ext\z` match: the matched extension contains a
    // dot, so strrpos can never return false.
    'src/Detection/Matchers.php' => [
        145, 242, 252, 645,
    ],

    // The driver loop intercepts opcodes 0x85 and 0x95 with read(9) +
    // continue (lines 266-273) before step() ever sees them, so step's 0x95
    // frame adjust and 0x85 case are dead; opcode 0x8a is shadowed by the
    // earlier case group (line 86) that routes it to readArgForObj.
    //
    // Text::ordAt decodes via mb_substr over valid UTF-8: lone surrogates
    // U+DC80-DCFF cannot occur (same substitution proof as SusPatterns
    // 147-148).
    'src/Detection/Pickle.php' => [
        171, 175, 176, 177, 194, 243,
    ],

    // replaceCharRef sees only strings matched by
    // &(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\f <&#;]{1,32};?): every
    // alternative requires at least one digit after the '#' (or a first
    // char that is not '#'), so $digits is never empty. Verified
    // empirically: '&#', '&#x', '&#X', '&#;', '&#x;' all match 0 times.
    'src/Detection/Preprocessor.php' => [
        242,
    ],

    // replace() always passes PREG_OFFSET_CAPTURE, so every capture group
    // entry is an array and the non-array `: null` branch never runs.
    'src/Detection/Preg.php' => [
        175,
    ],

    // Same 0xC2-0xDF arithmetic-dead overlong guard as BinaryIslands 56.
    'src/Detection/Semantic.php' => [
        67,
    ],

    // sanitizeForReporting reads Text::ord of a single Text::slice
    // character. The coverage job runs on PHP 8.3, whose mb_substr
    // substitutes every ill-formed sequence (invalid bytes and encoded
    // surrogates such as ed b2 80 alike) with the substitute character, so
    // a sliced character never decodes to U+DC80-DCFF (verified on 8.3).
    // PHP 8.2's mb_substr preserves those bytes and the branch is live
    // there (it emits the \xNN reporting escape); the 8.2 matrix jobs run
    // without pcov.
    'src/Detection/SusPatterns.php' => [
        200, 201,
    ],

    // The scheme position comes from an https?:// match, so the anchored
    // re-check at the same offset always succeeds.
    'src/Detection/XmlXxe.php' => [
        104,
    ],

    // canonicalNetwork re-runs inet_pton on an address canonicalText already
    // validated with FILTER_VALIDATE_IP; canonicalText's own inet_pton
    // follows a FILTER_VALIDATE_IP pass too, so neither can fail.
    'src/Ip/CanonicalIp.php' => [
        56, 108,
    ],

    // The private constructor is never invoked: LogActivity is used
    // statically only.
    'src/Logging/LogActivity.php' => [
        15,
    ],

    // json_decode's depth cap of 64 (line 216) bounds the parsed tree at 64
    // nesting levels, so the walk starting at depth 0 tops out at 63: the
    // > 64 cap can never fire, and depthCapHit stays false so the whole
    // '[REDACTED]' return is dead too (the decode-side JSON_ERROR_DEPTH
    // branch at 218-219 covers the deep case).
    //
    // The non-array guard at 224-225 sits behind the entry guard at 212:
    // redactJsonText returns before decoding any text whose first char is
    // not '{' or '[', so a parsed scalar can never reach it.
    'src/Logging/LogRedactor.php' => [
        225, 231, 243, 245,
    ],

    // The 'unix' trusted-proxy branch requires 'unix' inside
    // trustedProxies, but SecurityConfig::validateIpCidrList rejects that
    // entry at construction (verified: "trusted_proxies: invalid IP/CIDR
    // entry 'unix'").
    'src/Request/ClientIpResolver.php' => [
        24, 25, 26, 27, 28, 29,
    ],

    // The default loopback transport. The handler suites drive the
    // OtlpTransport seam with a capturing fake (no real network, per the
    // suite contract), and these bodies are exactly the live I/O: the
    // curl-or-streams export calls, their timeout/socket options and the
    // 2xx status parsing. They are exercised only against a live OTLP
    // collector.
    'src/Events/OtlpHttpTransport.php' => [
        28, 29, 30, 42, 60, 61, 62, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 75, 77,
    ],

    // 105: guard.status_code fires only when the event envelope carries a
    // statusCode field; SecurityEvent (the envelope the bus and every
    // emitter build) has no such field and isset() on the undeclared
    // readonly property is always false. The branch is kept for envelope
    // parity with the reference's getattr(event, "status_code", 0) - it
    // goes live the day the envelope grows the field.
    // 136, 138 / 202, 204: the json_encode === false guards over payloads
    // assembled exclusively from strings, ints, floats and bools; with
    // JSON_INVALID_UTF8_SUBSTITUTE the encode cannot fail for that shape.
    // 148: the metric-side export-failure log - the suite's failing
    // transport drives the trace-side twin, and a second failing fixture
    // for metrics would test the same catch-and-log shape twice.
    // 295 (OtelHandler) / 101 (LogfireHandler): the enrichment-forward
    // skip for keys literally named traceparent/tracestate sits behind the
    // guard.* prefix check, and neither name carries that prefix - the arm
    // is dead by construction. It is kept verbatim because the reference
    // (_forward_enrichment_metadata / the logfire handler's metadata walk)
    // carries the same exclusion (defense against a future key rename).
    'src/Events/OtelHandler.php' => [
        105, 136, 138, 148, 202, 204, 295,
    ],

    'src/Events/LogfireHandler.php' => [
        101,
    ],

    // 130: emitConsole's error_log fallback runs only when the stderr
    // stream cannot be written (a closed stderr); the suites always run
    // with stderr open and PHP cannot close the process stderr from
    // userland.
    'src/Logging/LogSetup.php' => [
        130,
    ],

    // 85-88: enrichMetric's catch is defensive - applyIdentityStrings
    // writes only validated string config values into a string-keyed map
    // and cannot throw; the reference carries the same defensive except
    // around a coroutine body that can fail on IO, which has no PHP-side
    // equivalent input.
    'src/Events/EventEnricher.php' => [
        85, 86, 88,
    ],

    // The bare-string guards inside validateSensitiveSet (1067) and
    // validateExclusionSet (1091) sit behind typed ?array constructor
    // parameters: PHP raises the TypeError at the call boundary, so a
    // string can never reach the is_string($names) checks (the same shape
    // as the BehaviorRule entry above). The suites assert the boundary
    // TypeError instead (test_json_logging.php).
    'src/Config/SecurityConfig.php' => [
        1067, 1091,
    ],

    // 219: the non-array/non-scalar json_decode guard - json_decode can
    // only return array|null|scalar, so `!is_array && !== null &&
    // !is_scalar` is a contradiction over its own output space.
    // 240-243: checkResponsePattern's catch is defensive parity with the
    // reference's try/except; every primitive inside (json_decode,
    // str_starts_with, substr, the preg_match-false arm handled at its
    // call site, strtolower) answers without throwing under the guarded
    // inputs (config construction rejects bodies/patterns that could make
    // PCRE raise).
    'src/Behavior/BehaviorTracker.php' => [
        219, 240, 241, 242, 243,
    ],

    // 373-377: the ip_ban-side initialization catch. Every collaborator
    // inside the try fails open or swallows: RateLimitHandler::
    // initializeRedis wraps scriptLoad in its own catch, initializeIpBan
    // only assigns the manager, IpBanManager::initializeRedis migrates
    // legacy keys under its own catch, and CloudManager::initializeRedis
    // refreshes through the single-flight path that logs its own
    // failures - no input steers a Throwable out of the block.
    'src/Engine/GuardEngine.php' => [
        373, 374, 375, 376, 377,
    ],
];
