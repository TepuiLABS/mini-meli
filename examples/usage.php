<?php

declare(strict_types=1);

/**
 * Ejemplo de uso de mini-meli con PHP 8.3
 *
 * Este archivo muestra cómo usar las nuevas funcionalidades
 * de la librería aprovechando las características de PHP 8.3
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Tepuilabs\MeliServices\Exceptions\GenericException;
use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliResponse;
use Tepuilabs\MeliServices\MeliServices;

// Configurar variables de entorno para el ejemplo
$_ENV['CLIENT_ID'] = 'tu_client_id_aqui';
$_ENV['CLIENT_SECRET'] = 'tu_client_secret_aqui';
$_ENV['CODE'] = 'codigo_de_autorizacion_aqui';
$_ENV['REDIRECT_URL'] = 'http://localhost:9000';

echo "=== Ejemplo de uso de mini-meli con PHP 8.3 ===\n\n";

// Ejemplo 1: Uso moderno con variables de entorno
echo "1. Uso moderno con variables de entorno:\n";

try {
    $meli = MeliServices::fromEnvironment();

    if ($meli->isValid()) {
        echo "✅ Configuración válida\n";

        // En un caso real, esto haría la petición HTTP
        // $response = $meli->generateAccessToken();
        // echo "Access Token: " . $response->getAccessToken() . "\n";

        echo "📋 Configuración actual:\n";
        $config = $meli->getConfig();
        echo '   - Client ID: ' . $config->clientId . "\n";
        echo '   - Redirect URI: ' . $config->redirectUri . "\n";
        echo '   - Grant Type: ' . $config->grantType . "\n";
    }
} catch (GenericException $e) {
    echo '❌ Error: ' . $e->getMessage() . "\n";
}

echo "\n";

// Ejemplo 2: Uso con configuración manual
echo "2. Uso con configuración manual:\n";

try {
    $config = new MeliConfig(
        clientId: 'test_client_id',
        clientSecret: 'test_client_secret',
        code: 'test_code',
        redirectUri: 'http://localhost:9000',
        grantType: 'authorization_code'
    );

    $meli = new MeliServices($config);
    echo "✅ Servicio creado exitosamente\n";

    // Mostrar configuración
    echo "📋 Configuración:\n";
    echo '   - Client ID: ' . $config->clientId . "\n";
    echo '   - Redirect URI: ' . $config->redirectUri . "\n";

} catch (GenericException $e) {
    echo '❌ Error: ' . $e->getMessage() . "\n";
}

echo "\n";

// Ejemplo 3: Uso con array (compatibilidad)
echo "3. Uso con array (compatibilidad):\n";

try {
    $params = [
        'client_id' => 'test_client_id',
        'client_secret' => 'test_client_secret',
        'code' => 'test_code',
        'redirect_uri' => 'http://localhost:9000',
        'grant_type' => 'authorization_code',
    ];

    $meli = MeliServices::fromArray($params);
    echo "✅ Servicio creado desde array\n";

} catch (GenericException $e) {
    echo '❌ Error: ' . $e->getMessage() . "\n";
}

echo "\n";

// Ejemplo 4: Manejo de respuestas
echo "4. Manejo de respuestas:\n";

try {
    // Simular una respuesta exitosa
    $responseData = [
        'access_token' => 'APP_USR-1234567890abcdef',
        'refresh_token' => 'TG-1234567890abcdef',
        'token_type' => 'Bearer',
        'expires_in' => 15552000,
        'scope' => 'read write',
        'user_id' => 123456789,
    ];

    $response = MeliResponse::fromArray($responseData);

    echo "✅ Respuesta procesada exitosamente\n";
    echo "📋 Datos de la respuesta:\n";
    echo '   - Access Token: ' . $response->getAccessToken() . "\n";
    echo '   - Refresh Token: ' . $response->getRefreshToken() . "\n";
    echo '   - Token Type: ' . $response->getTokenType() . "\n";
    echo '   - Expires In: ' . $response->getExpiresIn() . " segundos\n";
    echo '   - Scope: ' . $response->getScope() . "\n";
    echo '   - User ID: ' . $response->getUserId() . "\n";
    echo '   - Has Access Token: ' . ($response->hasAccessToken() ? 'Sí' : 'No') . "\n";
    echo '   - Is Successful: ' . ($response->isSuccessful() ? 'Sí' : 'No') . "\n";

    // Convertir a JSON
    echo '   - JSON: ' . $response->toJson() . "\n";

} catch (Exception $e) {
    echo '❌ Error: ' . $e->getMessage() . "\n";
}

echo "\n";

// Ejemplo 5: Manejo de errores
echo "5. Manejo de errores:\n";

try {
    // Simular una respuesta de error
    $errorData = [
        'error' => 'invalid_grant',
        'error_description' => 'The authorization code has expired',
        'status' => 400,
    ];

    $errorResponse = MeliResponse::fromArray($errorData, 400);

    echo "📋 Respuesta de error:\n";
    echo '   - Error: ' . $errorResponse->getErrorMessage() . "\n";
    echo '   - Description: ' . $errorResponse->getErrorDescription() . "\n";
    echo '   - Is Successful: ' . ($errorResponse->isSuccessful() ? 'Sí' : 'No') . "\n";

} catch (Exception $e) {
    echo '❌ Error: ' . $e->getMessage() . "\n";
}

echo "\n";

// Ejemplo 6: Validación de configuración
echo "6. Validación de configuración:\n";

try {
    // Configuración válida
    $validConfig = MeliConfig::fromArray([
        'client_id' => 'valid_id',
        'client_secret' => 'valid_secret',
        'code' => 'valid_code',
        'redirect_uri' => 'http://localhost:9000',
    ]);

    echo '✅ Configuración válida: ' . ($validConfig->isValid() ? 'Sí' : 'No') . "\n";

    // Configuración inválida
    $invalidConfig = MeliConfig::fromArray([
        'client_id' => 'valid_id',
        'client_secret' => 'valid_secret',
        'code' => 'valid_code',
        'redirect_uri' => 'invalid-url', // URL inválida
    ]);

} catch (GenericException $e) {
    echo '❌ Error de validación: ' . $e->getMessage() . "\n";
}

echo "\n";

// Ejemplo 7: Uso de excepciones específicas
echo "7. Uso de excepciones específicas:\n";

try {
    // Simular diferentes tipos de errores
    $missingParam = GenericException::missingParameter('client_id');
    echo '   - Missing Parameter: ' . $missingParam->getMessage() . "\n";

    $invalidResponse = GenericException::invalidApiResponse('Invalid JSON format');
    echo '   - Invalid Response: ' . $invalidResponse->getMessage() . "\n";

    $networkError = GenericException::networkError('Connection timeout');
    echo '   - Network Error: ' . $networkError->getMessage() . "\n";

} catch (Exception $e) {
    echo '❌ Error: ' . $e->getMessage() . "\n";
}

echo "\n=== Fin del ejemplo ===\n";
echo "\nPara usar en producción, asegúrate de:\n";
echo "1. Configurar las variables de entorno correctamente\n";
echo "2. Manejar las excepciones apropiadamente\n";
echo "3. Validar las respuestas antes de usarlas\n";
echo "4. Implementar refresh token cuando sea necesario\n";
