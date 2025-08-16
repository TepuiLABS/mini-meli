# 04. Refresh Tokens

## Introducción

Los refresh tokens permiten renovar access tokens sin que el usuario tenga que autorizar nuevamente tu aplicación. En este capítulo aprenderás cómo implementar esta funcionalidad usando la librería `mini-meli`.

## ¿Qué son los Refresh Tokens?

- **Access Token**: Válido por 6 horas, usado para llamadas a la API
- **Refresh Token**: Válido por 6 meses, usado para obtener nuevos access tokens
- **Offline Access**: Scope requerido para obtener refresh tokens

## 1. Verificar Disponibilidad de Refresh Token

Primero, verifica si tienes un refresh token disponible:

```php
<?php

session_start();

// Verificar si hay refresh token
if (!isset($_SESSION['refresh_token'])) {
    echo "❌ No hay refresh token disponible\n";
    echo "💡 El usuario debe autorizar con scope 'offline_access'\n";
    exit;
}

$refreshToken = $_SESSION['refresh_token'];
echo "✅ Refresh token encontrado: " . substr($refreshToken, 0, 20) . "...\n";
```

## 2. Configuración para Refresh Token

Crear una configuración específica para renovar tokens:

```php
<?php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;

require 'vendor/autoload.php';

// Configuración para refresh token
$config = new MeliConfig(
    clientId: 'tu_client_id',
    clientSecret: 'tu_client_secret',
    redirectUri: 'http://localhost:9000/callback',
    grantType: 'refresh_token',
    refreshToken: $refreshToken
);

// Verificar configuración
if (!$config->isValid()) {
    echo "❌ Configuración inválida para refresh token\n";
    exit;
}

echo "✅ Configuración válida para refresh token\n";
```

## 3. Renovar Access Token

Usar `MeliServices` para renovar el token:

```php
<?php

try {
    $meli = new MeliServices($config);

    // Renovar access token
    $response = $meli->refreshAccessToken($refreshToken);

    echo "✅ Token renovado exitosamente!\n";
    echo "Nuevo Access Token: " . substr($response->getAccessToken(), 0, 20) . "...\n";
    echo "Token Type: " . $response->getTokenType() . "\n";
    echo "Expires In: " . $response->getExpiresIn() . " segundos\n";
    echo "User ID: " . $response->getUserId() . "\n";
    echo "Scope: " . $response->getScope() . "\n";

    // El refresh token puede cambiar
    if ($response->hasRefreshToken()) {
        echo "Nuevo Refresh Token: " . substr($response->getRefreshToken(), 0, 20) . "...\n";
    }

} catch (GenericException $e) {
    echo "❌ Error al renovar token: " . $e->getMessage() . "\n";
    echo "Código de error: " . $e->getCode() . "\n";
}
```

## 4. Actualizar Sesión

Actualizar la sesión con los nuevos tokens:

```php
<?php

// Actualizar sesión con nuevos tokens
$_SESSION['access_token'] = $response->getAccessToken();
$_SESSION['token_type'] = $response->getTokenType();
$_SESSION['expires_in'] = $response->getExpiresIn();
$_SESSION['user_id'] = $response->getUserId();
$_SESSION['scope'] = $response->getScope();
$_SESSION['token_created'] = time(); // Marcar cuando se creó el token

// Actualizar refresh token si cambió
if ($response->hasRefreshToken()) {
    $_SESSION['refresh_token'] = $response->getRefreshToken();
}

echo "✅ Sesión actualizada con nuevos tokens\n";
```

## 5. Verificar Expiración Automática

Crear una función para verificar y renovar automáticamente:

```php
<?php

function checkAndRefreshToken(): bool {
    session_start();

    // Verificar si hay access token
    if (!isset($_SESSION['access_token'])) {
        return false;
    }

    // Verificar expiración
    $expiresIn = $_SESSION['expires_in'] ?? 0;
    $tokenCreated = $_SESSION['token_created'] ?? time();

    $timeElapsed = time() - $tokenCreated;
    $timeRemaining = $expiresIn - $timeElapsed;

    // Si expira en menos de 5 minutos, renovar
    if ($timeRemaining < 300) {
        echo "⚠️ Token expira en " . gmdate("H:i:s", $timeRemaining) . "\n";

        if (isset($_SESSION['refresh_token'])) {
            try {
                return refreshToken();
            } catch (Exception $e) {
                echo "❌ Error al renovar: " . $e->getMessage() . "\n";
                return false;
            }
        } else {
            echo "❌ No hay refresh token disponible\n";
            return false;
        }
    }

    echo "✅ Token válido por " . gmdate("H:i:s", $timeRemaining) . "\n";
    return true;
}

function refreshToken(): bool {
    $refreshToken = $_SESSION['refresh_token'];

    $config = new MeliConfig(
        clientId: 'tu_client_id',
        clientSecret: 'tu_client_secret',
        redirectUri: 'http://localhost:9000/callback',
        grantType: 'refresh_token',
        refreshToken: $refreshToken
    );

    $meli = new MeliServices($config);
    $response = $meli->refreshAccessToken($refreshToken);

    // Actualizar sesión
    $_SESSION['access_token'] = $response->getAccessToken();
    $_SESSION['token_type'] = $response->getTokenType();
    $_SESSION['expires_in'] = $response->getExpiresIn();
    $_SESSION['user_id'] = $response->getUserId();
    $_SESSION['scope'] = $response->getScope();
    $_SESSION['token_created'] = time();

    if ($response->hasRefreshToken()) {
        $_SESSION['refresh_token'] = $response->getRefreshToken();
    }

    echo "✅ Token renovado automáticamente\n";
    return true;
}
```

## 6. Middleware de Renovación Automática

Crear un middleware que renueve automáticamente los tokens:

```php
<?php
// auto_refresh_middleware.php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;
use Tepuilabs\MeliServices\Exceptions\GenericException;

function autoRefreshMiddleware(): void {
    session_start();

    // Verificar autenticación básica
    if (!isset($_SESSION['access_token'])) {
        header('Location: authorization.php');
        exit;
    }

    // Verificar expiración
    $expiresIn = $_SESSION['expires_in'] ?? 0;
    $tokenCreated = $_SESSION['token_created'] ?? time();

    $timeElapsed = time() - $tokenCreated;
    $timeRemaining = $expiresIn - $timeElapsed;

    // Renovar si expira en menos de 10 minutos
    if ($timeRemaining < 600) {
        if (isset($_SESSION['refresh_token'])) {
            try {
                autoRefreshToken();
            } catch (GenericException $e) {
                // Si falla la renovación, redirigir a autorización
                session_destroy();
                header('Location: authorization.php?error=token_expired');
                exit;
            }
        } else {
            // No hay refresh token, redirigir a autorización
            session_destroy();
            header('Location: authorization.php?error=no_refresh_token');
            exit;
        }
    }
}

function autoRefreshToken(): void {
    $refreshToken = $_SESSION['refresh_token'];

    $config = new MeliConfig(
        clientId: 'tu_client_id',
        clientSecret: 'tu_client_secret',
        redirectUri: 'http://localhost:9000/callback',
        grantType: 'refresh_token',
        refreshToken: $refreshToken
    );

    $meli = new MeliServices($config);
    $response = $meli->refreshAccessToken($refreshToken);

    // Actualizar sesión
    $_SESSION['access_token'] = $response->getAccessToken();
    $_SESSION['token_type'] = $response->getTokenType();
    $_SESSION['expires_in'] = $response->getExpiresIn();
    $_SESSION['user_id'] = $response->getUserId();
    $_SESSION['scope'] = $response->getScope();
    $_SESSION['token_created'] = time();

    if ($response->hasRefreshToken()) {
        $_SESSION['refresh_token'] = $response->getRefreshToken();
    }
}

// Uso en páginas protegidas
autoRefreshMiddleware();
echo "✅ Token válido y actualizado\n";
```

## 7. Manejo de Errores de Refresh Token

Los refresh tokens pueden fallar por varias razones:

```php
<?php

try {
    $response = $meli->refreshAccessToken($refreshToken);
} catch (GenericException $e) {
    $errorCode = $e->getCode();
    $errorMessage = $e->getMessage();

    switch ($errorCode) {
        case 400:
            if (strpos($errorMessage, 'invalid_grant') !== false) {
                echo "❌ Refresh token inválido o expirado\n";
                echo "💡 El usuario debe autorizar nuevamente\n";

                // Limpiar sesión
                session_destroy();
                header('Location: authorization.php');
                exit;

            } elseif (strpos($errorMessage, 'invalid_client') !== false) {
                echo "❌ Client ID o Client Secret inválidos\n";
                echo "💡 Verifica la configuración de tu aplicación\n";
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

## 8. Ejemplo de Clase TokenManager

Crear una clase para manejar tokens de forma más organizada:

```php
<?php
// TokenManager.php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;
use Tepuilabs\MeliServices\Exceptions\GenericException;

class TokenManager {
    private string $clientId;
    private string $clientSecret;
    private string $redirectUri;

    public function __construct(string $clientId, string $clientSecret, string $redirectUri) {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->redirectUri = $redirectUri;
    }

    public function isTokenValid(): bool {
        session_start();

        if (!isset($_SESSION['access_token'])) {
            return false;
        }

        $expiresIn = $_SESSION['expires_in'] ?? 0;
        $tokenCreated = $_SESSION['token_created'] ?? time();

        $timeElapsed = time() - $tokenCreated;
        return ($timeElapsed < $expiresIn);
    }

    public function isTokenExpiringSoon(): bool {
        session_start();

        $expiresIn = $_SESSION['expires_in'] ?? 0;
        $tokenCreated = $_SESSION['token_created'] ?? time();

        $timeElapsed = time() - $tokenCreated;
        $timeRemaining = $expiresIn - $timeElapsed;

        return ($timeRemaining < 600); // 10 minutos
    }

    public function refreshTokenIfNeeded(): bool {
        if (!$this->isTokenExpiringSoon()) {
            return true;
        }

        if (!isset($_SESSION['refresh_token'])) {
            return false;
        }

        try {
            return $this->refreshToken();
        } catch (Exception $e) {
            return false;
        }
    }

    public function refreshToken(): bool {
        session_start();

        $refreshToken = $_SESSION['refresh_token'];

        $config = new MeliConfig(
            clientId: $this->clientId,
            clientSecret: $this->clientSecret,
            redirectUri: $this->redirectUri,
            grantType: 'refresh_token',
            refreshToken: $refreshToken
        );

        $meli = new MeliServices($config);
        $response = $meli->refreshAccessToken($refreshToken);

        // Actualizar sesión
        $_SESSION['access_token'] = $response->getAccessToken();
        $_SESSION['token_type'] = $response->getTokenType();
        $_SESSION['expires_in'] = $response->getExpiresIn();
        $_SESSION['user_id'] = $response->getUserId();
        $_SESSION['scope'] = $response->getScope();
        $_SESSION['token_created'] = time();

        if ($response->hasRefreshToken()) {
            $_SESSION['refresh_token'] = $response->getRefreshToken();
        }

        return true;
    }

    public function getAccessToken(): ?string {
        session_start();
        return $_SESSION['access_token'] ?? null;
    }

    public function logout(): void {
        session_start();
        session_destroy();
    }
}

// Uso
$tokenManager = new TokenManager(
    'tu_client_id',
    'tu_client_secret',
    'http://localhost:9000/callback'
);

if (!$tokenManager->refreshTokenIfNeeded()) {
    header('Location: authorization.php');
    exit;
}

$accessToken = $tokenManager->getAccessToken();
echo "✅ Token válido: " . substr($accessToken, 0, 20) . "...\n";
```

## 9. Ejemplo de Página de Renovación Manual

Crear una página para renovar tokens manualmente:

```php
<?php
// refresh.php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;
use Tepuilabs\MeliServices\Exceptions\GenericException;

require 'vendor/autoload.php';

session_start();

$clientId = 'tu_client_id';
$clientSecret = 'tu_client_secret';
$redirectUri = 'http://localhost:9000/callback';

$success = false;
$error = null;

if (isset($_POST['refresh'])) {
    try {
        if (!isset($_SESSION['refresh_token'])) {
            throw new Exception("No hay refresh token disponible");
        }

        $refreshToken = $_SESSION['refresh_token'];

        $config = new MeliConfig(
            clientId: $clientId,
            clientSecret: $clientSecret,
            redirectUri: $redirectUri,
            grantType: 'refresh_token',
            refreshToken: $refreshToken
        );

        $meli = new MeliServices($config);
        $response = $meli->refreshAccessToken($refreshToken);

        // Actualizar sesión
        $_SESSION['access_token'] = $response->getAccessToken();
        $_SESSION['token_type'] = $response->getTokenType();
        $_SESSION['expires_in'] = $response->getExpiresIn();
        $_SESSION['user_id'] = $response->getUserId();
        $_SESSION['scope'] = $response->getScope();
        $_SESSION['token_created'] = time();

        if ($response->hasRefreshToken()) {
            $_SESSION['refresh_token'] = $response->getRefreshToken();
        }

        $success = true;

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Renovar Token - Mercado Libre</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .success { background: #d4edda; border: 1px solid #c3e6cb; padding: 20px; border-radius: 8px; }
        .error { background: #f8d7da; border: 1px solid #f5c6cb; padding: 20px; border-radius: 8px; }
        .info { background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 10px 0; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
    </style>
</head>
<body>
    <h1>🔄 Renovar Access Token</h1>

    <?php if ($success): ?>
        <div class="success">
            <h2>✅ Token Renovado Exitosamente</h2>
            <div class="info">
                <p><strong>Nuevo Access Token:</strong> <?= substr($_SESSION['access_token'], 0, 20) ?>...</p>
                <p><strong>Expira en:</strong> <?= $_SESSION['expires_in'] ?> segundos</p>
                <p><strong>User ID:</strong> <?= $_SESSION['user_id'] ?></p>
                <p><strong>Scope:</strong> <?= $_SESSION['scope'] ?></p>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($error): ?>
        <div class="error">
            <h2>❌ Error al Renovar Token</h2>
            <p><?= htmlspecialchars($error) ?></p>
        </div>
    <?php endif; ?>

    <div class="info">
        <h3>📋 Estado Actual del Token</h3>
        <?php if (isset($_SESSION['access_token'])): ?>
            <p><strong>Access Token:</strong> <?= substr($_SESSION['access_token'], 0, 20) ?>...</p>
            <p><strong>Expira en:</strong> <?= $_SESSION['expires_in'] ?? 'N/A' ?> segundos</p>
            <p><strong>Refresh Token:</strong> <?= isset($_SESSION['refresh_token']) ? 'Disponible' : 'No disponible' ?></p>
        <?php else: ?>
            <p>No hay token disponible</p>
        <?php endif; ?>
    </div>

    <form method="post">
        <button type="submit" name="refresh" class="btn">🔄 Renovar Token</button>
    </form>

    <p><a href="dashboard.php">Volver al Dashboard</a></p>
</body>
</html>
```

## 10. Mejores Prácticas

### Almacenamiento Seguro

```php
<?php

// ❌ Mal: Almacenar en texto plano
$_SESSION['access_token'] = $token;

// ✅ Bien: Usar variables de entorno para configuración
$config = MeliConfig::fromEnvironment();

// ✅ Bien: Limpiar tokens al cerrar sesión
function logout() {
    session_start();
    unset($_SESSION['access_token']);
    unset($_SESSION['refresh_token']);
    session_destroy();
}
```

### Renovación Proactiva

```php
<?php

// Renovar cuando falten 10 minutos para expirar
if ($timeRemaining < 600) {
    refreshToken();
}

// No esperar hasta el último momento
```

### Manejo de Errores

```php
<?php

try {
    refreshToken();
} catch (GenericException $e) {
    // Log del error
    error_log("Error refreshing token: " . $e->getMessage());

    // Redirigir a autorización
    header('Location: authorization.php');
    exit;
}
```

## Resumen

En este capítulo has aprendido:

- ✅ Qué son los refresh tokens y cómo funcionan
- ✅ Cómo verificar la disponibilidad de refresh tokens
- ✅ Renovación manual y automática de tokens
- ✅ Middleware para renovación automática
- ✅ Manejo de errores específicos
- ✅ Clase TokenManager para gestión organizada
- ✅ Página de renovación manual
- ✅ Mejores prácticas de seguridad

## Próximos Pasos

- [05. Llamadas a la API](./05-llamadas-api.md)
- [06. Gestión de Aplicaciones](./06-gestion-aplicaciones.md)
- [07. Manejo de Errores Avanzado](./07-manejo-errores-avanzado.md)
- [08. Seguridad y Mejores Prácticas](./08-seguridad-mejores-practicas.md)
