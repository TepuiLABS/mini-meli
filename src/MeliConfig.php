<?php

declare(strict_types=1);

namespace Tepuilabs\MeliServices;

use Tepuilabs\MeliServices\Exceptions\GenericException;

/**
 * Configuration class for Mercado Libre API
 */
final readonly class MeliConfig
{
    public function __construct(
        public string $clientId,
        public string $clientSecret,
        public string $code,
        public string $redirectUri,
        public string $grantType = 'authorization_code'
    ) {
        $this->validate();
    }

    /**
     * Create configuration from array
     *
     * @param array<string, string> $params
     */
    public static function fromArray(array $params): self
    {
        return new self(
            clientId: $params['client_id'] ?? '',
            clientSecret: $params['client_secret'] ?? '',
            code: $params['code'] ?? '',
            redirectUri: $params['redirect_uri'] ?? '',
            grantType: $params['grant_type'] ?? 'authorization_code'
        );
    }

    /**
     * Create configuration from environment variables
     */
    public static function fromEnvironment(): self
    {
        $clientId = $_ENV['CLIENT_ID'] ?? $_SERVER['CLIENT_ID'] ?? '';
        $clientSecret = $_ENV['CLIENT_SECRET'] ?? $_SERVER['CLIENT_SECRET'] ?? '';
        $code = $_ENV['CODE'] ?? $_SERVER['CODE'] ?? '';
        $redirectUri = $_ENV['REDIRECT_URL'] ?? $_SERVER['REDIRECT_URL'] ?? '';
        $grantType = $_ENV['GRANT_TYPE'] ?? $_SERVER['GRANT_TYPE'] ?? 'authorization_code';

        return new self(
            clientId: $clientId,
            clientSecret: $clientSecret,
            code: $code,
            redirectUri: $redirectUri,
            grantType: $grantType
        );
    }

    /**
     * Convert to array for API request
     *
     * @return array<string, string>
     */
    public function toArray(): array
    {
        return [
            'grant_type' => $this->grantType,
            'client_id' => $this->clientId,
            'code' => $this->code,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->redirectUri,
        ];
    }

    /**
     * Validate configuration parameters
     */
    private function validate(): void
    {
        $requiredFields = [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code' => $this->code,
            'redirect_uri' => $this->redirectUri,
        ];

        foreach ($requiredFields as $field => $value) {
            if (empty(trim($value))) {
                throw GenericException::missingParameter($field);
            }
        }

        if (! filter_var($this->redirectUri, FILTER_VALIDATE_URL)) {
            throw new GenericException('La URL de redirección no es válida');
        }
    }

    /**
     * Check if configuration is valid
     */
    public function isValid(): bool
    {
        try {
            $this->validate();

            return true;
        } catch (GenericException) {
            return false;
        }
    }
}
