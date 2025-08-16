<?php

declare(strict_types=1);

namespace Tepuilabs\MeliServices;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use Tepuilabs\MeliServices\Exceptions\GenericException;

final class MeliServices
{
    private const MERCADO_LIBRE_API_BASE_URI = 'https://api.mercadolibre.com/';

    private const OAUTH_TOKEN_ENDPOINT = 'oauth/token';

    public function __construct(
        private readonly MeliConfig $config
    ) {
    }

    /**
     * Create MeliServices from array parameters (backward compatibility)
     *
     * @param array<string, string> $params
     */
    public static function fromArray(array $params): self
    {
        return new self(MeliConfig::fromArray($params));
    }

    /**
     * Create MeliServices from environment variables
     */
    public static function fromEnvironment(): self
    {
        return new self(MeliConfig::fromEnvironment());
    }

    /**
     * Generate access token for Mercado Libre API
     *
     * @throws GenericException|GuzzleException
     */
    public function generateAccessToken(): MeliResponse
    {
        $responseData = $this->makeHttpRequest($this->config->toArray());

        return MeliResponse::fromArray($responseData);
    }

    /**
     * Refresh access token using refresh token
     *
     * @throws GenericException|GuzzleException
     */
    public function refreshAccessToken(string $refreshToken): MeliResponse
    {
        $refreshConfig = new MeliConfig(
            clientId: $this->config->clientId,
            clientSecret: $this->config->clientSecret,
            grantType: 'refresh_token',
            refreshToken: $refreshToken
        );

        $refreshService = new MeliServices($refreshConfig);
        $responseData = $refreshService->makeHttpRequest($refreshConfig->toArray());

        return MeliResponse::fromArray($responseData);
    }

    /**
     * Generate authorization URL for OAuth 2.0 flow
     *
     * @param string $site Mercado Libre site (MLA, MLB, MLM, etc.)
     * @param array<string, string> $additionalParams Additional parameters
     * @throws GenericException
     */
    public function getAuthorizationUrl(string $site, array $additionalParams = []): string
    {
        if (empty($this->config->clientId)) {
            throw GenericException::missingParameter('client_id');
        }

        if (empty($this->config->redirectUri)) {
            throw GenericException::missingParameter('redirect_uri');
        }

        if (!MeliSites::isValid($site)) {
            throw new GenericException("Site '{$site}' no es válido. Use: " . implode(', ', array_keys(MeliSites::getAll())));
        }

        $params = [
            'response_type' => 'code',
            'client_id' => $this->config->clientId,
            'redirect_uri' => $this->config->redirectUri,
        ];

        // Add PKCE parameters if available
        if ($this->config->hasPkce()) {
            $params['code_challenge'] = $this->config->codeChallenge;
            $params['code_challenge_method'] = 'S256';
        }

        // Add state if available
        if ($this->config->hasState()) {
            $params['state'] = $this->config->state;
        }

        // Add scopes if provided
        if (!empty($this->config->scopes)) {
            $params['scope'] = $this->config->getScopesString();
        }

        // Add additional parameters
        $params = array_merge($params, $additionalParams);

        $queryString = http_build_query($params);
        $authUrl = MeliSites::getAuthorizationUrl($site);

        return "{$authUrl}?{$queryString}";
    }

    /**
     * Get application details
     *
     * @throws GenericException|GuzzleException
     */
    public function getApplicationDetails(string $accessToken, string | int $appId): array
    {
        return $this->apiCall("/applications/{$appId}", $accessToken, 'GET');
    }

    /**
     * Get applications authorized by user
     *
     * @throws GenericException|GuzzleException
     */
    public function getUserApplications(string $accessToken, string | int $userId): array
    {
        return $this->apiCall("/users/{$userId}/applications", $accessToken, 'GET');
    }

    /**
     * Get users who granted permissions to your application
     *
     * @throws GenericException|GuzzleException
     */
    public function getApplicationGrants(string $accessToken, string | int $appId): array
    {
        return $this->apiCall("/applications/{$appId}/grants", $accessToken, 'GET');
    }

    /**
     * Revoke user authorization for your application
     *
     * @throws GenericException|GuzzleException
     */
    public function revokeUserAuthorization(string $accessToken, string | int $userId, string $appId): array
    {
        return $this->apiCall("/users/{$userId}/applications/{$appId}", $accessToken, 'DELETE');
    }

    /**
     * Generate access token and return as array (backward compatibility)
     *
     * @throws GenericException|GuzzleException
     * @return array<string, mixed>
     */
    public function generateAccessTokenArray(): array
    {
        return $this->generateAccessToken()->toArray();
    }

    /**
     * Make API call to Mercado Libre with access token
     *
     * @param string $endpoint API endpoint (e.g., '/users/me')
     * @param string $accessToken Access token for authentication
     * @param string $method HTTP method (GET, POST, PUT, DELETE)
     * @param array<string, mixed> $data Request data for POST/PUT requests
     * @throws GenericException|GuzzleException
     * @return array<string, mixed>
     */
    public function apiCall(string $endpoint, string $accessToken, string $method = 'GET', array $data = []): array
    {
        $client = new Client([
            'base_uri' => MeliSites::getApiUrl(),
            'timeout' => 30,
            'connect_timeout' => 10,
        ]);

        $options = [
            'headers' => [
                'Authorization' => "Bearer {$accessToken}",
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
            ],
        ];

        if (!empty($data) && in_array($method, ['POST', 'PUT', 'PATCH'])) {
            $options['json'] = $data;
        }

        try {
            $response = $client->request($method, ltrim($endpoint, '/'), $options);
            $body = $response->getBody()->getContents();
            $responseData = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

            if (!is_array($responseData)) {
                throw GenericException::invalidApiResponse();
            }

            return $responseData;

        } catch (RequestException $e) {
            $statusCode = $e->getResponse()?->getStatusCode();
            $errorMessage = match ($statusCode) {
                400 => 'Solicitud inválida - verifica los parámetros enviados',
                401 => 'Token inválido o expirado - verifica tu access token',
                403 => 'Acceso denegado - verifica los permisos de tu aplicación',
                404 => 'Endpoint no encontrado',
                429 => 'Demasiadas solicitudes - intenta más tarde',
                500, 502, 503, 504 => 'Error del servidor de Mercado Libre - intenta más tarde',
                default => "Error HTTP {$statusCode}: " . $e->getMessage(),
            };

            throw new GenericException($errorMessage, $statusCode ?? 0, $e);
        } catch (Exception $e) {
            throw GenericException::networkError($e->getMessage());
        }
    }

    /**
     * Make GET request to Mercado Libre API
     *
     * @param string $endpoint API endpoint
     * @param string $accessToken Access token
     * @throws GenericException|GuzzleException
     * @return array<string, mixed>
     */
    public function get(string $endpoint, string $accessToken): array
    {
        return $this->apiCall($endpoint, $accessToken, 'GET');
    }

    /**
     * Make POST request to Mercado Libre API
     *
     * @param string $endpoint API endpoint
     * @param string $accessToken Access token
     * @param array<string, mixed> $data Request data
     * @throws GenericException|GuzzleException
     * @return array<string, mixed>
     */
    public function post(string $endpoint, string $accessToken, array $data = []): array
    {
        return $this->apiCall($endpoint, $accessToken, 'POST', $data);
    }

    /**
     * Make PUT request to Mercado Libre API
     *
     * @param string $endpoint API endpoint
     * @param string $accessToken Access token
     * @param array<string, mixed> $data Request data
     * @throws GenericException|GuzzleException
     * @return array<string, mixed>
     */
    public function put(string $endpoint, string $accessToken, array $data = []): array
    {
        return $this->apiCall($endpoint, $accessToken, 'PUT', $data);
    }

    /**
     * Make DELETE request to Mercado Libre API
     *
     * @param string $endpoint API endpoint
     * @param string $accessToken Access token
     * @throws GenericException|GuzzleException
     * @return array<string, mixed>
     */
    public function delete(string $endpoint, string $accessToken): array
    {
        return $this->apiCall($endpoint, $accessToken, 'DELETE');
    }

    /**
     * Make HTTP request to Mercado Libre API
     *
     * @param array<string, string> $fields
     * @throws GenericException|GuzzleException
     * @return array<string, mixed>
     */
    private function makeHttpRequest(array $fields): array
    {
        $client = new Client([
            'base_uri' => MeliSites::getApiUrl(),
            'timeout' => 30,
            'connect_timeout' => 10,
        ]);

        try {
            $response = $client->post(self::OAUTH_TOKEN_ENDPOINT, [
                'form_params' => $fields,
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
            ]);

            $body = $response->getBody()->getContents();
            $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

            if (! is_array($data)) {
                throw GenericException::invalidApiResponse();
            }

            return $data;

        } catch (RequestException $e) {
            $statusCode = $e->getResponse()?->getStatusCode();
            $errorMessage = match ($statusCode) {
                400 => 'Solicitud inválida - verifica los parámetros enviados',
                401 => 'Credenciales inválidas - verifica client_id y client_secret',
                403 => 'Acceso denegado - verifica los permisos de tu aplicación',
                404 => 'Endpoint no encontrado',
                429 => 'Demasiadas solicitudes - intenta más tarde',
                500, 502, 503, 504 => 'Error del servidor de Mercado Libre - intenta más tarde',
                default => "Error HTTP {$statusCode}: " . $e->getMessage(),
            };

            throw new GenericException($errorMessage, $statusCode ?? 0, $e);
        } catch (Exception $e) {
            throw GenericException::networkError($e->getMessage());
        }
    }

    /**
     * Get the current configuration
     */
    public function getConfig(): MeliConfig
    {
        return $this->config;
    }

    /**
     * Check if configuration is valid
     */
    public function isValid(): bool
    {
        return $this->config->isValid();
    }
}
