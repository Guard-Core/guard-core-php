<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\SecurityHeaders;

/**
 * Security headers management, ported from the reference
 * guard_core/handlers/security_headers_handler.py plus its config mixin
 * (_security_headers_config.py) and the field defaults of
 * SecurityConfig.security_headers (_security_config_fields.py). The engine
 * owns the logic (responseHeaders()); adapters apply the map to their
 * outgoing responses, mirroring the reference response factory's
 * process_response/apply_security_headers.
 *
 * The config array shape mirrors the reference security_headers dict keys:
 * enabled, hsts ({max_age, include_subdomains, preload}), csp (an
 * insertion-ordered map of directive => source list), frame_options,
 * content_type_options, xss_protection, referrer_policy,
 * permissions_policy and custom (a map of name => value).
 *
 * Per-header semantics (reference _compute_default_headers): an absent or
 * null override keeps the class default, a string value (validated and
 * sanitized) replaces the header; permissions_policy is three-way, an
 * absent key keeps the class default ("UNSET"), an explicit null or empty
 * string removes the header (the reference falsy check), and any other
 * value overrides it. Custom headers land last and may override anything.
 */
final class SecurityHeadersPolicy
{
    /** Reference SecurityHeadersManager.default_headers, in table order. */
    public const CLASS_DEFAULT_HEADERS = [
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'SAMEORIGIN',
        'X-XSS-Protection' => '1; mode=block',
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Permissions-Policy' => 'geolocation=(), microphone=(), camera=()',
        'X-Permitted-Cross-Domain-Policies' => 'none',
        'X-Download-Options' => 'noopen',
        'Cross-Origin-Embedder-Policy' => 'require-corp',
        'Cross-Origin-Opener-Policy' => 'same-origin',
        'Cross-Origin-Resource-Policy' => 'same-origin',
    ];

    private const HEADER_VALUE_MAX_BYTES = 8192;

    public readonly bool $enabled;

    /** @var array{max_age: int, include_subdomains: bool, preload: bool}|null null = no Strict-Transport-Security header */
    public readonly ?array $hsts;

    /** @var array<string, list<string>> */
    public readonly array $csp;

    public readonly ?string $frameOptions;

    public readonly ?string $contentTypeOptions;

    public readonly ?string $xssProtection;

    public readonly ?string $referrerPolicy;

    /**
     * Three-way permissions-policy value: null keeps the class default,
     * '' removes the header, any other value overrides it.
     */
    public readonly ?string $permissionsPolicy;

    /** @var array<string, string> */
    public readonly array $custom;

    /**
     * @param array<string, mixed>|null $config the reference-shaped
     * security_headers dict; null builds the reference default block
     * (enabled with the class defaults plus HSTS max-age=31536000;
     * includeSubDomains)
     */
    public function __construct(?array $config = null)
    {
        $config = $config ?? self::defaultConfig();
        $this->enabled = $config['enabled'] ?? true;
        $this->hsts = self::computeHsts($config['hsts'] ?? null);
        $this->csp = self::computeCsp($config['csp'] ?? null);
        $this->frameOptions = self::validatedOverride($config['frame_options'] ?? null, 'frame_options');
        $this->contentTypeOptions = self::validatedOverride($config['content_type_options'] ?? null, 'content_type_options');
        $this->xssProtection = self::validatedOverride($config['xss_protection'] ?? null, 'xss_protection');
        $this->referrerPolicy = self::validatedOverride($config['referrer_policy'] ?? null, 'referrer_policy');
        $permissions = $config['permissions_policy'] ?? null;
        if (is_string($permissions)) {
            $permissions = self::validateHeaderValue($permissions);
        }
        $this->permissionsPolicy = $permissions;
        $this->custom = self::computeCustom($config['custom'] ?? null);
    }

    /** @return array<string, mixed> */
    public static function defaultConfig(): array
    {
        return [
            'enabled' => true,
            'hsts' => [
                'max_age' => 31536000,
                'include_subdomains' => true,
                'preload' => false,
            ],
            'csp' => null,
            'frame_options' => 'SAMEORIGIN',
            'content_type_options' => 'nosniff',
            'xss_protection' => '1; mode=block',
            'referrer_policy' => 'strict-origin-when-cross-origin',
            'permissions_policy' => 'geolocation=(), microphone=(), camera=()',
            'custom' => null,
        ];
    }

    /**
     * Mirrors _validate_header_name: the name must be a non-empty RFC 7230
     * token.
     */
    public static function validateHeaderName(string $name): string
    {
        if (preg_match("/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/", $name) !== 1) {
            throw new \InvalidArgumentException("Invalid header name: {$name}");
        }

        return $name;
    }

    /**
     * Mirrors _validate_header_value: no CR/LF, at most 8192 bytes, control
     * characters below 0x20 dropped except tab.
     */
    public static function validateHeaderValue(string $value): string
    {
        if (str_contains($value, "\r") || str_contains($value, "\n")) {
            throw new \InvalidArgumentException("Invalid header value contains newline: {$value}");
        }
        if (strlen($value) > self::HEADER_VALUE_MAX_BYTES) {
            throw new \InvalidArgumentException('Header value too long: ' . strlen($value) . ' bytes');
        }
        $out = '';
        $length = strlen($value);
        for ($i = 0; $i < $length; $i++) {
            $char = $value[$i];
            if (ord($char) >= 32 || $char === "\t") {
                $out .= $char;
            }
        }

        return $out;
    }

    /**
     * Computes the security header map for a config, mirroring
     * SecurityHeadersManager.get_headers resolved against the reference
     * security_headers dict: disabled configuration yields no headers, the
     * class defaults apply, the CSP and HSTS blocks extend them, and the
     * custom headers land last (overriding everything).
     *
     * @return array<string, string>
     */
    public function responseHeaders(): array
    {
        if (!$this->enabled) {
            return [];
        }
        $headers = self::CLASS_DEFAULT_HEADERS;
        foreach ([
            'X-Frame-Options' => $this->frameOptions,
            'X-Content-Type-Options' => $this->contentTypeOptions,
            'X-XSS-Protection' => $this->xssProtection,
            'Referrer-Policy' => $this->referrerPolicy,
        ] as $name => $override) {
            if ($override !== null) {
                $headers[$name] = $override;
            }
        }
        if ($this->permissionsPolicy === '') {
            unset($headers['Permissions-Policy']);
        } elseif ($this->permissionsPolicy !== null) {
            $headers['Permissions-Policy'] = $this->permissionsPolicy;
        }
        $csp = $this->buildCsp();
        if ($csp !== '') {
            $headers['Content-Security-Policy'] = $csp;
        }
        $hsts = $this->buildHsts();
        if ($hsts !== '') {
            $headers['Strict-Transport-Security'] = $hsts;
        }
        foreach ($this->custom as $name => $value) {
            $headers[$name] = $value;
        }

        return $headers;
    }

    /**
     * Mirrors _build_hsts on the _compute_hsts_config result (the preload
     * corrections are applied in computeHsts).
     */
    private function buildHsts(): string
    {
        $hsts = $this->hsts;
        if ($hsts === null) {
            return '';
        }
        $parts = ['max-age=' . $hsts['max_age']];
        if ($hsts['include_subdomains']) {
            $parts[] = 'includeSubDomains';
        }
        if ($hsts['preload']) {
            $parts[] = 'preload';
        }

        return implode('; ', $parts);
    }

    /**
     * Mirrors _build_csp: "directive source1 source2" joined with "; ",
     * bare directives kept when they carry no sources.
     */
    private function buildCsp(): string
    {
        $directives = [];
        foreach ($this->csp as $directive => $sources) {
            if ($sources !== []) {
                $directives[] = $directive . ' ' . implode(' ', $sources);
            } else {
                $directives[] = $directive;
            }
        }

        return implode('; ', $directives);
    }

    /**
     * Mirrors _compute_hsts_config plus the _build_hsts input contract: no
     * max_age means no Strict-Transport-Security header; the preload
     * corrections downgrade preload below one year and force
     * includeSubDomains (the reference logs both; the PHP config has no
     * warn channel, so the warning rides error_log like guard-core-go's
     * log.Printf).
     *
     * @return array{max_age: int, include_subdomains: bool, preload: bool}|null
     */
    private static function computeHsts(mixed $hsts): ?array
    {
        if (!is_array($hsts)) {
            return null;
        }
        $maxAge = $hsts['max_age'] ?? null;
        if ($maxAge === null) {
            return null;
        }
        if (!is_int($maxAge)) {
            throw new \InvalidArgumentException('security_headers[hsts]: max_age must be an int');
        }
        $includeSubdomains = $hsts['include_subdomains'] ?? true;
        $preload = $hsts['preload'] ?? false;
        if ($preload) {
            if ($maxAge < 31536000) {
                error_log('HSTS preload requires max_age >= 31536000');
                $preload = false;
            }
            if (!$includeSubdomains) {
                error_log('HSTS preload requires includeSubDomains');
                $includeSubdomains = true;
            }
        }

        return ['max_age' => $maxAge, 'include_subdomains' => $includeSubdomains, 'preload' => $preload];
    }

    /**
     * Mirrors _compute_csp_config: a falsy CSP is no CSP; unsafe sources
     * log the reference warning.
     *
     * @return array<string, list<string>>
     */
    private static function computeCsp(mixed $csp): array
    {
        if (!is_array($csp) || $csp === []) {
            return [];
        }
        $out = [];
        foreach ($csp as $directive => $sources) {
            if (!is_string($directive) || !is_array($sources)) {
                throw new \InvalidArgumentException('security_headers[csp]: map of directive => list of sources');
            }
            foreach ($sources as $source) {
                if (!is_string($source)) {
                    throw new \InvalidArgumentException("security_headers[csp]: '{$directive}' sources must be strings");
                }
            }
            if (in_array("'unsafe-inline'", $sources, true) || in_array("'unsafe-eval'", $sources, true)) {
                error_log("CSP directive '{$directive}' contains unsafe sources");
            }
            $out[$directive] = $sources;
        }

        return $out;
    }

    /**
     * Mirrors _compute_custom_headers: names must be RFC 7230 tokens and
     * values are validated/sanitized.
     *
     * @return array<string, string>
     */
    private static function computeCustom(mixed $custom): array
    {
        if ($custom === null) {
            return [];
        }
        if (!is_array($custom)) {
            throw new \InvalidArgumentException('security_headers[custom]: map of header name => value');
        }
        $out = [];
        foreach ($custom as $name => $value) {
            if (!is_string($name) || !is_string($value)) {
                throw new \InvalidArgumentException('security_headers[custom]: map of header name => string value');
            }
            $out[self::validateHeaderName($name)] = self::validateHeaderValue($value);
        }

        return $out;
    }

    /**
     * A null override keeps the class default (the reference dict lookup
     * returning None); a string override is validated and sanitized in
     * place, mirroring configure() raising out of _validate_header_value.
     */
    private static function validatedOverride(mixed $value, string $field): ?string
    {
        if ($value === null) {
            return null;
        }
        if (!is_string($value)) {
            throw new \InvalidArgumentException("security_headers[{$field}]: override must be a string or null");
        }

        return self::validateHeaderValue($value);
    }
}
