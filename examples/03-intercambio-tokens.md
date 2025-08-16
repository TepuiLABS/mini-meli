# 03. Intercambio de Tokens

## Introducción

Una vez que el usuario autoriza tu aplicación, Mercado Libre te devuelve un código de autorización. En este capítulo aprenderás cómo intercambiar ese código por un access token usando la librería `mini-meli`.

## Flujo de Intercambio

1. **Usuario autoriza** → Mercado Libre devuelve `code`
2. **Intercambiar código** → Obtener `access_token`
3. **Usar token** → Hacer llamadas a la API

## 1. Procesar el Callback

Cuando el usuario regresa de Mercado Libre, recibes un código de autorización:

```php
<?php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;
use Tepuilabs\MeliServices\MeliResponse;
use Tepuilabs\MeliServices\Exceptions\GenericException;

require 'vendor/autoload.php';

session_start();

// Verificar que tenemos el código
if (!isset($_GET['code'])) {
    die("❌ No se recibió código de autorización");
}

$code = $_GET['code'];
$state = $_GET['state'] ?? '';

// Verificar state (protección CSRF)
$savedState = $_SESSION['state'] ?? '';
if ($state !== $savedState) {
    die("❌ State no coincide. Posible ataque CSRF");
}

// Obtener code_verifier de la sesión
$codeVerifier = $_SESSION['code_verifier'] ?? '';
if (empty($codeVerifier)) {
    die("❌ No se encontró code_verifier en la sesión");
}

echo "✅ Código recibido: " . substr($code, 0, 20) . "...\n";
echo "✅ State validado\n";
echo "✅ Code verifier encontrado\n";
```

## 2. Crear Configuración para Intercambio

Necesitas una configuración específica para el intercambio de tokens:

```php
<?php

// Configuración para intercambio de tokens
$config = new MeliConfig(
    clientId: 'tu_client_id',
    clientSecret: 'tu_client_secret',
    code: $code,
    redirectUri: 'http://localhost:9000/callback',
    codeVerifier: $codeVerifier, // Requerido para PKCE
    scopes: ['read', 'write', 'offline_access']
);

// Verificar que la configuración es válida
if (!$config->isValid()) {
    die("❌ Configuración inválida para intercambio de tokens");
}

echo "✅ Configuración válida para intercambio\n";
echo "Es para intercambio: " . ($config->isForTokenExchange() ? 'Sí' : 'No') . "\n";
```

## 3. Intercambiar Código por Token

Usar `MeliServices` para hacer el intercambio:

```php
<?php

try {
    $meli = new MeliServices($config);

    // Intercambiar código por token
    $response = $meli->generateAccessToken();

    echo "✅ Token obtenido exitosamente!\n";
    echo "Access Token: " . substr($response->getAccessToken(), 0, 20) . "...\n";
    echo "Token Type: " . $response->getTokenType() . "\n";
    echo "Expires In: " . $response->getExpiresIn() . " segundos\n";
    echo "User ID: " . $response->getUserId() . "\n";
    echo "Scope: " . $response->getScope() . "\n";

    if ($response->hasRefreshToken()) {
        echo "Refresh Token: " . substr($response->getRefreshToken(), 0, 20) . "...\n";
    }

} catch (GenericException $e) {
    echo "❌ Error al obtener token: " . $e->getMessage() . "\n";
    echo "Código de error: " . $e->getCode() . "\n";
}
```

## 4. Guardar Tokens en Sesión

Es importante guardar los tokens para usarlos después:

```php
<?php

// Guardar tokens en sesión
$_SESSION['access_token'] = $response->getAccessToken();
$_SESSION['token_type'] = $response->getTokenType();
$_SESSION['expires_in'] = $response->getExpiresIn();
$_SESSION['user_id'] = $response->getUserId();
$_SESSION['scope'] = $response->getScope();

// Guardar refresh token si está disponible
if ($response->hasRefreshToken()) {
    $_SESSION['refresh_token'] = $response->getRefreshToken();
}

// Limpiar datos de PKCE
unset($_SESSION['code_verifier']);
unset($_SESSION['state']);

echo "✅ Tokens guardados en sesión\n";
echo "✅ Datos de PKCE limpiados\n";
```

## 5. Validar la Respuesta

La librería incluye métodos para validar la respuesta:

```php
<?php

// Validar que la respuesta es exitosa
if (!$response->isSuccessful()) {
    echo "❌ La respuesta no fue exitosa\n";
    echo "Error: " . $response->getErrorMessage() . "\n";
    echo "Descripción: " . $response->getErrorDescription() . "\n";
    exit;
}

// Verificar que tenemos access token
if (!$response->hasAccessToken()) {
    echo "❌ No se recibió access token\n";
    exit;
}

// Verificar scopes
$scopes = $response->getScope();
if (strpos($scopes, 'offline_access') !== false) {
    echo "✅ Offline access habilitado\n";
} else {
    echo "⚠️ Offline access no habilitado (no habrá refresh tokens)\n";
}

echo "✅ Respuesta validada correctamente\n";
```

## 6. Ejemplo Completo de Callback

Aquí tienes un ejemplo completo del archivo de callback:

```php
<?php
// callback.php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;
use Tepuilabs\MeliServices\MeliResponse;
use Tepuilabs\MeliServices\Exceptions\GenericException;

require 'vendor/autoload.php';

session_start();

// Configuración
$clientId = 'tu_client_id';
$clientSecret = 'tu_client_secret';
$redirectUri = 'http://localhost:9000/callback';

try {
    // Paso 1: Verificar parámetros
    if (!isset($_GET['code'])) {
        throw new Exception("No se recibió código de autorización");
    }

    $code = $_GET['code'];
    $state = $_GET['state'] ?? '';

    // Paso 2: Validar state
    $savedState = $_SESSION['state'] ?? '';
    if ($state !== $savedState) {
        throw new Exception("State no coincide. Posible ataque CSRF");
    }

    // Paso 3: Obtener code_verifier
    $codeVerifier = $_SESSION['code_verifier'] ?? '';
    if (empty($codeVerifier)) {
        throw new Exception("No se encontró code_verifier en la sesión");
    }

    // Paso 4: Crear configuración
    $config = new MeliConfig(
        clientId: $clientId,
        clientSecret: $clientSecret,
        code: $code,
        redirectUri: $redirectUri,
        codeVerifier: $codeVerifier,
        scopes: ['read', 'write', 'offline_access']
    );

    // Paso 5: Intercambiar token
    $meli = new MeliServices($config);
    $response = $meli->generateAccessToken();

    // Paso 6: Validar respuesta
    if (!$response->isSuccessful()) {
        throw new Exception("Error en la respuesta: " . $response->getErrorMessage());
    }

    // Paso 7: Guardar en sesión
    $_SESSION['access_token'] = $response->getAccessToken();
    $_SESSION['token_type'] = $response->getTokenType();
    $_SESSION['expires_in'] = $response->getExpiresIn();
    $_SESSION['user_id'] = $response->getUserId();
    $_SESSION['scope'] = $response->getScope();

    if ($response->hasRefreshToken()) {
        $_SESSION['refresh_token'] = $response->getRefreshToken();
    }

    // Paso 8: Limpiar datos de PKCE
    unset($_SESSION['code_verifier']);
    unset($_SESSION['state']);

    $success = true;

} catch (Exception $e) {
    $error = $e->getMessage();
    $success = false;
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Callback - Mercado Libre OAuth</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .success { background: #d4edda; border: 1px solid #c3e6cb; padding: 20px; border-radius: 8px; }
        .error { background: #f8d7da; border: 1px solid #f5c6cb; padding: 20px; border-radius: 8px; }
        .token-info { background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 10px 0; }
    </style>
</head>
<body>
    <?php if ($success): ?>
        <div class="success">
            <h1>✅ ¡Autenticación Exitosa!</h1>
            <p>Has sido autenticado correctamente con Mercado Libre.</p>

            <div class="token-info">
                <h3>📋 Información del Token</h3>
                <p><strong>Access Token:</strong> <?= substr($_SESSION['access_token'], 0, 20) ?>...</p>
                <p><strong>Token Type:</strong> <?= $_SESSION['token_type'] ?></p>
                <p><strong>Expires In:</strong> <?= $_SESSION['expires_in'] ?> segundos</p>
                <p><strong>User ID:</strong> <?= $_SESSION['user_id'] ?></p>
                <p><strong>Scope:</strong> <?= $_SESSION['scope'] ?></p>
                <?php if (isset($_SESSION['refresh_token'])): ?>
                    <p><strong>Refresh Token:</strong> <?= substr($_SESSION['refresh_token'], 0, 20) ?>...</p>
                <?php endif; ?>
            </div>

            <p><a href="dashboard.php">Ir al Dashboard</a></p>
        </div>
    <?php else: ?>
        <div class="error">
            <h1>❌ Error de Autenticación</h1>
            <p><?= htmlspecialchars($error) ?></p>
            <p><a href="authorization.php">Intentar nuevamente</a></p>
        </div>
    <?php endif; ?>
</body>
</html>
```

## 7. Manejo de Errores Específicos

La librería maneja diferentes tipos de errores:

```php
<?php

try {
    $response = $meli->generateAccessToken();
} catch (GenericException $e) {
    $errorCode = $e->getCode();
    $errorMessage = $e->getMessage();

    switch ($errorCode) {
        case 400:
            if (strpos($errorMessage, 'invalid_grant') !== false) {
                echo "❌ Código de autorización inválido o expirado\n";
                echo "💡 El usuario debe autorizar nuevamente\n";
            } elseif (strpos($errorMessage, 'invalid_client') !== false) {
                echo "❌ Client ID o Client Secret inválidos\n";
                echo "💡 Verifica la configuración de tu aplicación\n";
            } elseif (strpos($errorMessage, 'invalid_redirect_uri') !== false) {
                echo "❌ Redirect URI no coincide\n";
                echo "💡 Verifica la URL configurada en tu aplicación\n";
            }
            break;

        case 401:
            echo "❌ No autorizado\n";
            echo "💡 Verifica las credenciales de tu aplicación\n";
            break;

        case 429:
            echo "❌ Demasiadas solicitudes\n";
            echo "💡 Espera un momento antes de intentar nuevamente\n";
            break;

        default:
            echo "❌ Error desconocido: {$errorMessage}\n";
    }
}
```

## 8. Verificar Expiración del Token

Los tokens de Mercado Libre expiran en 6 horas (21600 segundos):

```php
<?php

// Verificar si el token está próximo a expirar
$expiresIn = $_SESSION['expires_in'] ?? 0;
$tokenCreated = $_SESSION['token_created'] ?? time();

$timeElapsed = time() - $tokenCreated;
$timeRemaining = $expiresIn - $timeElapsed;

if ($timeRemaining < 300) { // 5 minutos
    echo "⚠️ El token expirará pronto\n";
    echo "Tiempo restante: " . gmdate("H:i:s", $timeRemaining) . "\n";

    if (isset($_SESSION['refresh_token'])) {
        echo "💡 Usa el refresh token para renovar\n";
    } else {
        echo "💡 El usuario debe autorizar nuevamente\n";
    }
} else {
    echo "✅ Token válido por " . gmdate("H:i:s", $timeRemaining) . "\n";
}
```

## 9. Convertir Respuesta a Array

Si necesitas trabajar con arrays en lugar de objetos:

```php
<?php

// Obtener respuesta como array
$responseArray = $response->toArray();

echo "Respuesta como array:\n";
print_r($responseArray);

// O usar el método directo de MeliServices
$responseArray = $meli->generateAccessTokenArray();

echo "Respuesta directa como array:\n";
print_r($responseArray);
```

## 10. Ejemplo de Middleware de Autenticación

Aquí tienes un ejemplo de middleware para verificar autenticación:

```php
<?php
// auth_middleware.php

function checkAuthentication(): bool {
    session_start();

    // Verificar si hay access token
    if (!isset($_SESSION['access_token'])) {
        return false;
    }

    // Verificar expiración
    $expiresIn = $_SESSION['expires_in'] ?? 0;
    $tokenCreated = $_SESSION['token_created'] ?? time();

    $timeElapsed = time() - $tokenCreated;
    if ($timeElapsed >= $expiresIn) {
        // Token expirado, limpiar sesión
        session_destroy();
        return false;
    }

    return true;
}

function requireAuth(): void {
    if (!checkAuthentication()) {
        header('Location: authorization.php');
        exit;
    }
}

// Uso en páginas protegidas
requireAuth();
echo "✅ Usuario autenticado\n";
```

## Resumen

En este capítulo has aprendido:

- ✅ Cómo procesar el callback de OAuth
- ✅ Validación de state para seguridad
- ✅ Intercambio de código por access token
- ✅ Manejo de respuestas y errores
- ✅ Almacenamiento seguro de tokens
- ✅ Verificación de expiración
- ✅ Middleware de autenticación
- ✅ Ejemplo completo de callback

## Próximos Pasos

- [04. Refresh Tokens](./04-refresh-tokens.md)
- [05. Llamadas a la API](./05-llamadas-api.md)
- [06. Gestión de Aplicaciones](./06-gestion-aplicaciones.md)
- [07. Manejo de Errores Avanzado](./07-manejo-errores-avanzado.md)
