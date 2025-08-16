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
        public string $code = '',
        public string $redirectUri = '',
        public string $grantType = 'authorization_code',
        public string $codeVerifier = '',
        public string $codeChallenge = '',
        public string $state = '',
        public string $refreshToken = '',
        public array $scopes = []
    ) {
        $this->validate();
    }

    /**
     * Create configuration from array
     *
     * @param array<string, string|array> $params
     */
    public static function fromArray(array $params): self
    {
        $scopes = [];
        if (isset($params['scopes'])) {
            $scopes = is_array($params['scopes'])
                ? $params['scopes']
                : MeliScopes::toArray($params['scopes']);
        }

        return new self(
            clientId: $params['client_id'] ?? '',
            clientSecret: $params['client_secret'] ?? '',
            code: $params['code'] ?? '',
            redirectUri: $params['redirect_uri'] ?? '',
            grantType: $params['grant_type'] ?? 'authorization_code',
            codeVerifier: $params['code_verifier'] ?? '',
            codeChallenge: $params['code_challenge'] ?? '',
            state: $params['state'] ?? '',
            refreshToken: $params['refresh_token'] ?? '',
            scopes: $scopes
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
        $codeVerifier = $_ENV['CODE_VERIFIER'] ?? $_SERVER['CODE_VERIFIER'] ?? '';
        $codeChallenge = $_ENV['CODE_CHALLENGE'] ?? $_SERVER['CODE_CHALLENGE'] ?? '';
        $state = $_ENV['STATE'] ?? $_SERVER['STATE'] ?? '';
        $refreshToken = $_ENV['REFRESH_TOKEN'] ?? $_SERVER['REFRESH_TOKEN'] ?? '';

        $scopes = [];
        if (isset($_ENV['SCOPES']) || isset($_SERVER['SCOPES'])) {
            $scopesString = $_ENV['SCOPES'] ?? $_SERVER['SCOPES'] ?? '';
            $scopes = MeliScopes::toArray($scopesString);
        }

        return new self(
            clientId: $clientId,
            clientSecret: $clientSecret,
            code: $code,
            redirectUri: $redirectUri,
            grantType: $grantType,
            codeVerifier: $codeVerifier,
            codeChallenge: $codeChallenge,
            state: $state,
            refreshToken: $refreshToken,
            scopes: $scopes
        );
    }

    /**
     * Create configuration for authorization URL generation (without code)
     */
    public static function forAuthorization(
        string $clientId,
        string $clientSecret,
        string $redirectUri,
        string $codeVerifier = '',
        string $codeChallenge = '',
        string $state = '',
        array $scopes = []
    ): self {
        return new self(
            clientId: $clientId,
            clientSecret: $clientSecret,
            code: '', // Not needed for authorization URL
            redirectUri: $redirectUri,
            grantType: 'authorization_code',
            codeVerifier: $codeVerifier,
            codeChallenge: $codeChallenge,
            state: $state,
            refreshToken: '',
            scopes: $scopes
        );
    }

    /**
     * Generate PKCE code verifier and challenge
     *
     * @return array{code_verifier: string, code_challenge: string}
     */
    public static function generatePkce(): array
    {
        $codeVerifier = bin2hex(random_bytes(32));
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

        return [
            'code_verifier' => $codeVerifier,
            'code_challenge' => $codeChallenge,
        ];
    }

    /**
     * Generate random state for CSRF protection
     */
    public static function generateState(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Convert to array for API request
     *
     * @return array<string, string>
     */
    public function toArray(): array
    {
        $params = [
            'grant_type' => $this->grantType,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        // Add parameters based on grant type
        switch ($this->grantType) {
            case 'authorization_code':
                $params['code'] = $this->code;
                $params['redirect_uri'] = $this->redirectUri;
                if (!empty($this->codeVerifier)) {
                    $params['code_verifier'] = $this->codeVerifier;
                }

                break;
            case 'refresh_token':
                $params['refresh_token'] = $this->refreshToken;

                break;
        }

        return $params;
    }

    /**
     * Validate configuration parameters
     */
    private function validate(): void
    {
        $requiredFields = [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];

        // Add validation based on grant type
        switch ($this->grantType) {
            case 'authorization_code':
                // Only require code and redirect_uri if we're actually making a token request
                if (!empty($this->code)) {
                    $requiredFields['code'] = $this->code;
                    $requiredFields['redirect_uri'] = $this->redirectUri;
                } elseif (!empty($this->redirectUri)) {
                    // For authorization URL generation, only redirect_uri is required
                    $requiredFields['redirect_uri'] = $this->redirectUri;
                }

                break;
            case 'refresh_token':
                $requiredFields['refresh_token'] = $this->refreshToken;

                break;
            default:
                throw new GenericException("Grant type '{$this->grantType}' no es soportado. Use 'authorization_code' o 'refresh_token'");
        }

        foreach ($requiredFields as $field => $value) {
            if (empty(trim($value))) {
                throw GenericException::missingParameter($field);
            }
        }

        if (!empty($this->redirectUri) && !filter_var($this->redirectUri, FILTER_VALIDATE_URL)) {
            throw new GenericException('La URL de redirección no es válida');
        }

        // Validate scopes if provided
        if (!empty($this->scopes) && !MeliScopes::validateScopes($this->scopes)) {
            throw new GenericException('Los scopes proporcionados no son válidos. Use: ' . implode(', ', MeliScopes::getAll()));
        }

        // Validate PKCE parameters
        if (!empty($this->codeVerifier) && empty($this->codeChallenge)) {
            throw new GenericException('code_challenge es requerido cuando se proporciona code_verifier');
        }

        if (!empty($this->codeChallenge) && empty($this->codeVerifier)) {
            throw new GenericException('code_verifier es requerido cuando se proporciona code_challenge');
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

    /**
     * Check if PKCE is enabled
     */
    public function hasPkce(): bool
    {
        return !empty($this->codeVerifier) && !empty($this->codeChallenge);
    }

    /**
     * Check if state is present
     */
    public function hasState(): bool
    {
        return !empty($this->state);
    }

    /**
     * Check if refresh token is present
     */
    public function hasRefreshToken(): bool
    {
        return !empty($this->refreshToken);
    }

    /**
     * Check if this is for token exchange (has code)
     */
    public function isForTokenExchange(): bool
    {
        return !empty($this->code);
    }

    /**
     * Get scopes as string
     */
    public function getScopesString(): string
    {
        return MeliScopes::toString($this->scopes);
    }

    /**
     * Check if scopes include offline access
     */
    public function hasOfflineAccess(): bool
    {
        return MeliScopes::hasOfflineAccess($this->scopes);
    }

    /**
     * Check if scopes include read permission
     */
    public function hasReadPermission(): bool
    {
        return MeliScopes::hasRead($this->scopes);
    }

    /**
     * Check if scopes include write permission
     */
    public function hasWritePermission(): bool
    {
        return MeliScopes::hasWrite($this->scopes);
    }
}
