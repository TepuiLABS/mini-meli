<?php

declare(strict_types=1);

use Tepuilabs\MeliServices\Exceptions\GenericException;
use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliResponse;
use Tepuilabs\MeliServices\MeliServices;

beforeEach(function () {
    $this->validParams = [
        'client_id' => 'test_client_id',
        'client_secret' => 'test_client_secret',
        'code' => 'test_code',
        'redirect_uri' => 'http://localhost:9000',
        'grant_type' => 'authorization_code',
    ];
});

describe('MeliConfig', function () {
    it('creates valid configuration from array', function () {
        $config = MeliConfig::fromArray($this->validParams);

        expect($config)
            ->clientId->toBe('test_client_id')
            ->clientSecret->toBe('test_client_secret')
            ->code->toBe('test_code')
            ->redirectUri->toBe('http://localhost:9000')
            ->grantType->toBe('authorization_code');
    });

    it('throws exception for missing required parameters', function () {
        $invalidParams = [
            'client_id' => 'test_client_id',
            // missing other required params
        ];

        expect(fn () => MeliConfig::fromArray($invalidParams))
            ->toThrow(GenericException::class, "El parámetro 'client_secret' es requerido");
    });

    it('throws exception for invalid redirect URI', function () {
        $invalidParams = $this->validParams;
        $invalidParams['redirect_uri'] = 'invalid-url';

        expect(fn () => MeliConfig::fromArray($invalidParams))
            ->toThrow(GenericException::class, 'La URL de redirección no es válida');
    });

    it('validates configuration correctly', function () {
        $config = MeliConfig::fromArray($this->validParams);
        expect($config->isValid())->toBeTrue();
    });

    it('converts to array correctly', function () {
        $config = MeliConfig::fromArray($this->validParams);
        $array = $config->toArray();

        expect($array)->toHaveKeys([
            'grant_type',
            'client_id',
            'code',
            'client_secret',
            'redirect_uri',
        ]);
    });
});

describe('MeliResponse', function () {
    it('creates response from array', function () {
        $data = [
            'access_token' => 'test_token',
            'refresh_token' => 'refresh_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ];

        $response = MeliResponse::fromArray($data);

        expect($response)
            ->getAccessToken()->toBe('test_token')
            ->getRefreshToken()->toBe('refresh_token')
            ->getTokenType()->toBe('Bearer')
            ->getExpiresIn()->toBe(3600);
    });

    it('handles missing optional fields', function () {
        $data = ['access_token' => 'test_token'];
        $response = MeliResponse::fromArray($data);

        expect($response)
            ->getRefreshToken()->toBeNull()
            ->getTokenType()->toBeNull();
    });

    it('checks for access token presence', function () {
        $responseWithToken = MeliResponse::fromArray(['access_token' => 'test']);
        $responseWithoutToken = MeliResponse::fromArray(['error' => 'invalid_grant']);

        expect($responseWithToken->hasAccessToken())->toBeTrue()
            ->and($responseWithoutToken->hasAccessToken())->toBeFalse();
    });

    it('converts to JSON correctly', function () {
        $data = ['access_token' => 'test_token', 'expires_in' => 3600];
        $response = MeliResponse::fromArray($data);

        $json = $response->toJson();
        expect($json)->toBe('{"access_token":"test_token","expires_in":3600}');
    });

    it('identifies successful responses', function () {
        $successResponse = MeliResponse::fromArray(['access_token' => 'test'], 200);
        $errorResponse = MeliResponse::fromArray(['error' => 'invalid_grant'], 400);

        expect($successResponse->isSuccessful())->toBeTrue()
            ->and($errorResponse->isSuccessful())->toBeFalse();
    });
});

describe('MeliServices', function () {
    it('creates service from array', function () {
        $service = MeliServices::fromArray($this->validParams);

        expect($service)
            ->toBeInstanceOf(MeliServices::class)
            ->isValid()->toBeTrue();
    });

    it('provides backward compatibility with array return', function () {
        $service = MeliServices::fromArray($this->validParams);

        // This would normally make a real HTTP request, so we're just testing the method exists
        expect(method_exists($service, 'generateAccessTokenArray'))->toBeTrue();
    });

    it('returns configuration object', function () {
        $service = MeliServices::fromArray($this->validParams);
        $config = $service->getConfig();

        expect($config)
            ->toBeInstanceOf(MeliConfig::class)
            ->clientId->toBe('test_client_id');
    });
});

describe('GenericException', function () {
    it('creates missing parameter exception', function () {
        $exception = GenericException::missingParameter('client_id');

        expect($exception->getMessage())->toBe("El parámetro 'client_id' es requerido");
    });

    it('creates invalid API response exception', function () {
        $exception = GenericException::invalidApiResponse('Invalid JSON');

        expect($exception->getMessage())->toBe('Respuesta inválida de la API de Mercado Libre: Invalid JSON');
    });

    it('creates network error exception', function () {
        $exception = GenericException::networkError('Connection timeout');

        expect($exception->getMessage())->toBe('Error de conexión con Mercado Libre: Connection timeout');
    });
});
