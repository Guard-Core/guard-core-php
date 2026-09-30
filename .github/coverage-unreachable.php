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

    // The constructor pre-seeds ipRanges/networkRegions for every registry
    // provider (array_fill_keys(PROVIDERS, []), lines 45-46), and every
    // internal caller passes registry-validated provider lists
    // (SecurityConfig::validateBlockCloudProviders), so the post-catch
    // !array_key_exists guards are always false.
    //
    // details() walks bareProviderNames of the same registry-validated
    // lists: a bare name is always a PROVIDERS member, hence a pre-seeded
    // key, so the skip never runs.
    'src/Cloud/CloudManager.php' => [
        136, 137, 190, 191, 307,
    ],

    // curl_init only fails when the cURL extension is missing.
    'src/Cloud/CurlHttpClient.php' => [
        22,
    ],

    // Bare-string guards behind ?array parameters: PHP rejects a string
    // argument with a TypeError before the body runs.
    'src/Config/SecurityConfig.php' => [
        881, 905,
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
    // 122-123).
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

    // sanitizeForReporting reads Text::ord of a single Text::slice character
    // (mb_strcut output, always valid UTF-8): surrogates cannot occur.
    //
    // A per-pattern scan timeout needs one pattern scan >= 0.9 * 2.0s; the
    // whole corpus on adversarial inputs up to 840KB stays under 0.2s per
    // pattern (size-gated recon patterns anchor at \A and cap at 15KB), and
    // the collected $timeouts are never read by detect() anyway.
    'src/Detection/SusPatterns.php' => [
        122, 123, 361,
    ],

    // The scheme position comes from an https?:// match, so the anchored
    // re-check at the same offset always succeeds.
    'src/Detection/XmlXxe.php' => [
        104,
    ],

    // The constructor always builds the BehavioralProcessor (line 76), so
    // the null guard is dead.
    'src/Engine/GuardEngine.php' => [
        180,
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

    // Formats a pattern_timeout threat, but no code path constructs a threat
    // with that type (grep: only this formatter mentions pattern_timeout).
    'src/Pipeline/Checks/SuspiciousActivityCheck.php' => [
        341, 343,
    ],

    // The 'unix' trusted-proxy branch requires 'unix' inside
    // trustedProxies, but SecurityConfig::validateIpCidrList rejects that
    // entry at construction (verified: "trusted_proxies: invalid IP/CIDR
    // entry 'unix'").
    'src/Request/ClientIpResolver.php' => [
        24, 25, 26, 27, 28, 29,
    ],
];
