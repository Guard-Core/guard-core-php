<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Events;

/**
 * The OTLP/HTTP export seam (the PHP stand-in for the reference's
 * opentelemetry exporter objects): one POST per export call, the payload is
 * the OTLP/HTTP JSON encoding (protobuf JSON mapping), the response body is
 * ignored - success is a 2xx. Implementations must not throw for a failed
 * export (return false); the handler treats false exactly like the
 * reference treats a silent exporter failure (logged, never propagated).
 */
interface OtlpTransport
{
    /**
     * POST the OTLP/HTTP JSON payload to the signal endpoint.
     *
     * @param string $endpoint absolute OTLP/HTTP signal URL (…/v1/traces or …/v1/metrics)
     * @param string $payload  JSON-encoded OTLP request body
     *
     * @return bool true when the exporter answered 2xx
     */
    public function export(string $endpoint, string $payload): bool;
}
