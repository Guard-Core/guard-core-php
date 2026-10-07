<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Redis;

final class GuardRedisException extends \RenzoFranceschini\GuardCore\Exceptions\GuardCoreError
{
    /**
     * Whether the failure is transient (connect/write/read/timeout) and
     * therefore retryable under the redis_retries backoff, mirroring the
     * reference Retry(ExponentialBackoff(), retries) which retries
     * connection-class errors but never server-side error replies. The
     * RESP client marks its connect/write/read failures transient at the
     * throw sites; every other producer defaults to false.
     */
    public readonly bool $transient;

    public function __construct(string $message, int $code = 503, ?\Throwable $previous = null, bool $transient = false)
    {
        parent::__construct($message, $code, $previous);
        $this->transient = $transient;
    }
}
