<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Events;

/**
 * The default OTLP/HTTP JSON transport: curl when the extension is loaded,
 * the streams fallback otherwise. Timeouts bound the export so a dead
 * collector cannot hang a request; failures return false (never throw).
 */
final class OtlpHttpTransport implements OtlpTransport
{
    public function __construct(
        private readonly float $timeoutSeconds = 2.0,
        /** @var array<string, string> */
        private readonly array $headers = ['Content-Type' => 'application/json']
    ) {
    }

    public function export(string $endpoint, string $payload): bool
    {
        try {
            if (function_exists('curl_init')) {
                return $this->exportWithCurl($endpoint, $payload);
            }

            return $this->exportWithStreams($endpoint, $payload);
        } catch (\Throwable) {
            return false;
        }
    }

    private function exportWithCurl(string $endpoint, string $payload): bool
    {
        $headers = [];
        foreach ($this->headers as $name => $value) {
            $headers[] = $name . ': ' . $value;
        }
        $ch = curl_init($endpoint);
        if ($ch === false) {
            return false;
        }
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_CONNECTTIMEOUT => $this->timeoutSeconds,
        ]);
        $ok = curl_exec($ch) !== false && curl_getinfo($ch, CURLINFO_RESPONSE_CODE) >= 200 && curl_getinfo($ch, CURLINFO_RESPONSE_CODE) < 300;
        curl_close($ch);

        return $ok;
    }

    private function exportWithStreams(string $endpoint, string $payload): bool
    {
        $headers = '';
        foreach ($this->headers as $name => $value) {
            $headers .= $name . ': ' . $value . "\r\n";
        }
        $context = stream_context_create(['http' => [
            'method' => 'POST',
            'header' => $headers,
            'content' => $payload,
            'ignore_errors' => true,
            'timeout' => $this->timeoutSeconds,
        ]]);
        $response = @file_get_contents($endpoint, false, $context);
        if ($response === false) {
            return false;
        }
        $statusLine = $http_response_header[0] ?? '';

        return preg_match('#\s2\d\d\s#', $statusLine) === 1;
    }
}
