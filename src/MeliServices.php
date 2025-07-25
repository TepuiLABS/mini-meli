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
     * Make HTTP request to Mercado Libre API
     *
     * @param array<string, string> $fields
     * @throws GenericException|GuzzleException
     * @return array<string, mixed>
     */
    private function makeHttpRequest(array $fields): array
    {
        $client = new Client([
            'base_uri' => self::MERCADO_LIBRE_API_BASE_URI,
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
