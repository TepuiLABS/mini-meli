<?php

declare(strict_types=1);

namespace Tepuilabs\MeliServices;

/**
 * Response wrapper for Mercado Libre API
 */
final readonly class MeliResponse
{
    /**
     * @param array<string, mixed> $data
     */
    public function __construct(
        public array $data,
        public int $statusCode = 200
    ) {
    }

    /**
     * Create response from array
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data, int $statusCode = 200): self
    {
        return new self($data, $statusCode);
    }

    /**
     * Get access token from response
     */
    public function getAccessToken(): ?string
    {
        return $this->data['access_token'] ?? null;
    }

    /**
     * Get refresh token from response
     */
    public function getRefreshToken(): ?string
    {
        return $this->data['refresh_token'] ?? null;
    }

    /**
     * Get token type from response
     */
    public function getTokenType(): ?string
    {
        return $this->data['token_type'] ?? null;
    }

    /**
     * Get expires in seconds from response
     */
    public function getExpiresIn(): ?int
    {
        return $this->data['expires_in'] ?? null;
    }

    /**
     * Get scope from response
     */
    public function getScope(): ?string
    {
        return $this->data['scope'] ?? null;
    }

    /**
     * Get user ID from response
     */
    public function getUserId(): ?int
    {
        return $this->data['user_id'] ?? null;
    }

    /**
     * Check if response contains access token
     */
    public function hasAccessToken(): bool
    {
        return $this->getAccessToken() !== null;
    }

    /**
     * Check if response contains refresh token
     */
    public function hasRefreshToken(): bool
    {
        return $this->getRefreshToken() !== null;
    }

    /**
     * Get all response data
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->data;
    }

    /**
     * Get response as JSON string
     */
    public function toJson(): string
    {
        return json_encode($this->data, JSON_THROW_ON_ERROR);
    }

    /**
     * Check if response is successful
     */
    public function isSuccessful(): bool
    {
        return $this->statusCode >= 200 && $this->statusCode < 300;
    }

    /**
     * Get error message if any
     */
    public function getErrorMessage(): ?string
    {
        return $this->data['error'] ?? $this->data['message'] ?? null;
    }

    /**
     * Get error description if any
     */
    public function getErrorDescription(): ?string
    {
        return $this->data['error_description'] ?? null;
    }
}
