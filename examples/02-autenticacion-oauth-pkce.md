# 02. Autenticación OAuth 2.0 PKCE

## Introducción

OAuth 2.0 PKCE (Proof Key for Code Exchange) es un flujo de autenticación seguro que previene ataques de interceptación de código. En este capítulo aprenderás cómo implementar este flujo completo usando la librería `mini-meli`.

## ¿Qué es PKCE?

PKCE es una extensión del flujo OAuth 2.0 que agrega una capa adicional de seguridad:

- **Code Verifier**: Una cadena aleatoria generada por el cliente
- **Code Challenge**: Un hash del code verifier que se envía en la URL de autorización
- **Verificación**: El servidor verifica que el code verifier coincida con el challenge

## 1. Generación de PKCE y State

El primer paso es generar los valores necesarios para PKCE y protección CSRF:

```php
<?php

use Tepuilabs\MeliServices\MeliConfig;

require 'vendor/autoload.php';

// Generar PKCE
$pkce = MeliConfig::generatePkce();

echo "Code Verifier: " . $pkce['code_verifier'] . "\n";
echo "Code Challenge: " . $pkce['code_challenge'] . "\n";

// Generar State para protección CSRF
$state = MeliConfig::generateState();
echo "State: " . $state . "\n";

// Guardar en sesión para usar después
session_start();
$_SESSION['code_verifier'] = $pkce['code_verifier'];
$_SESSION['state'] = $state;
```

### Detalles Técnicos

- **Code Verifier**: 32 bytes aleatorios, base64url encoded
- **Code Challenge**: SHA-256 hash del verifier, base64url encoded
- **State**: 16 bytes aleatorios para protección CSRF

## 2. Configuración para Autorización

Crear una configuración específica para generar URLs de autorización:

```php
<?php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;
use Tepuilabs\MeliServices\MeliScopes;

require 'vendor/autoload.php';

// Configuración para autorización
$config = MeliConfig::forAuthorization(
    clientId: 'tu_client_id',
    clientSecret: 'tu_client_secret',
    redirectUri: 'http://localhost:9000/callback',
    codeVerifier: $pkce['code_verifier'],
    codeChallenge: $pkce['code_challenge'],
    state: $state,
    scopes: MeliScopes::getOfflineAccess() // Incluye refresh tokens
);

$meli = new MeliServices($config);
```

## 3. Generar URL de Autorización

Crear la URL que redirigirá al usuario a Mercado Libre:

```php
<?php

use Tepuilabs\MeliServices\MeliSites;

require 'vendor/autoload.php';

// Generar URL para Argentina
$authUrl = $meli->getAuthorizationUrl('MLA');

echo "URL de autorización:\n";
echo $authUrl . "\n";

// También puedes generar URLs para otros países
$sites = MeliSites::getAll();
foreach ($sites as $siteId => $siteInfo) {
    $url = $meli->getAuthorizationUrl($siteId);
    echo "{$siteInfo['name']} ({$siteInfo['flag']}): " . substr($url, 0, 80) . "...\n";
}
```

### URL Generada

La URL generada incluye todos los parámetros necesarios:

```
https://auth.mercadolibre.com.ar/authorization?
response_type=code&
client_id=tu_client_id&
redirect_uri=http://localhost:9000/callback&
code_challenge=tu_code_challenge&
code_challenge_method=S256&
state=tu_state&
scope=read write offline_access
```

## 4. Sitios Soportados

La librería soporta todos los sitios de Mercado Libre:

```php
<?php

use Tepuilabs\MeliServices\MeliSites;

require 'vendor/autoload.php';

$sites = MeliSites::getAll();

foreach ($sites as $siteId => $siteInfo) {
    echo "{$siteId} - {$siteInfo['name']} {$siteInfo['flag']}\n";
    echo "  Dominio: {$siteInfo['domain']}\n";
    echo "  URL: " . MeliSites::getAuthorizationUrl($siteId) . "\n\n";
}
```

### Sitios Disponibles

| Código | País | Bandera | Dominio |
|--------|------|---------|---------|
| MLA | Argentina | 🇦🇷 | ar |
| MLB | Brasil | 🇧🇷 | br |
| MLM | México | 🇲🇽 | mx |
| MLC | Chile | 🇨🇱 | cl |
| MCO | Colombia | 🇨🇴 | co |
| MPE | Perú | 🇵🇪 | pe |
| MLU | Uruguay | 🇺🇾 | uy |
| MLV | Venezuela | 🇻🇪 | ve |

## 5. Ejemplo Completo de Autorización

Aquí tienes un ejemplo completo del flujo de autorización:

```php
<?php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;
use Tepuilabs\MeliServices\MeliScopes;
use Tepuilabs\MeliServices\MeliSites;

require 'vendor/autoload.php';

session_start();

// Configuración
$clientId = 'tu_client_id';
$clientSecret = 'tu_client_secret';
$redirectUri = 'http://localhost:9000/callback';

// Paso 1: Si no hay código, generar URL de autorización
if (!isset($_GET['code'])) {
    // Generar PKCE y State
    $pkce = MeliConfig::generatePkce();
    $state = MeliConfig::generateState();

    // Guardar en sesión
    $_SESSION['code_verifier'] = $pkce['code_verifier'];
    $_SESSION['state'] = $state;

    // Crear configuración
    $config = MeliConfig::forAuthorization(
        clientId: $clientId,
        clientSecret: $clientSecret,
        redirectUri: $redirectUri,
        codeVerifier: $pkce['code_verifier'],
        codeChallenge: $pkce['code_challenge'],
        state: $state,
        scopes: MeliScopes::getOfflineAccess()
    );

    $meli = new MeliServices($config);

    // Generar URL de autorización
    $authUrl = $meli->getAuthorizationUrl('MLA'); // Argentina

    echo "🔐 Ve a esta URL para autorizar:\n";
    echo $authUrl . "\n";
    echo "\nO haz clic aquí: <a href='{$authUrl}'>Autorizar con Mercado Libre</a>\n";

    exit;
}

// Paso 2: Procesar callback (se ejecuta después de la autorización)
echo "✅ Callback recibido\n";
echo "Código: " . $_GET['code'] . "\n";
echo "State: " . $_GET['state'] . "\n";
```

## 6. Validación de State

Es crucial validar el parámetro `state` para prevenir ataques CSRF:

```php
<?php

session_start();

// Verificar state
$receivedState = $_GET['state'] ?? '';
$savedState = $_SESSION['state'] ?? '';

if (empty($savedState)) {
    die("❌ Error: No se encontró el state en la sesión");
}

if ($receivedState !== $savedState) {
    die("❌ Error: El state no coincide. Posible ataque CSRF");
}

echo "✅ State validado correctamente\n";

// Limpiar state de la sesión
unset($_SESSION['state']);
```

## 7. Manejo de Errores de OAuth

Mercado Libre puede devolver errores en el callback:

```php
<?php

// Verificar si hay errores de OAuth
if (isset($_GET['error'])) {
    $error = $_GET['error'];
    $errorDescription = $_GET['error_description'] ?? 'Error desconocido';

    echo "❌ Error de OAuth: {$error}\n";
    echo "Descripción: {$errorDescription}\n";

    // Manejar errores específicos
    switch ($error) {
        case 'access_denied':
            echo "El usuario canceló la autorización\n";
            break;
        case 'invalid_request':
            echo "Parámetros inválidos en la solicitud\n";
            break;
        case 'unauthorized_client':
            echo "Cliente no autorizado\n";
            break;
        case 'unsupported_response_type':
            echo "Tipo de respuesta no soportado\n";
            break;
        case 'invalid_scope':
            echo "Scope inválido\n";
            break;
        case 'server_error':
            echo "Error del servidor de Mercado Libre\n";
            break;
        case 'temporarily_unavailable':
            echo "Servicio temporalmente no disponible\n";
            break;
        default:
            echo "Error desconocido\n";
    }

    exit;
}
```

## 8. Parámetros Adicionales

Puedes agregar parámetros adicionales a la URL de autorización:

```php
<?php

// Parámetros adicionales
$additionalParams = [
    'prompt' => 'consent', // Forzar pantalla de consentimiento
    'login_hint' => 'usuario@email.com', // Sugerir email
];

$authUrl = $meli->getAuthorizationUrl('MLA', $additionalParams);

echo "URL con parámetros adicionales:\n";
echo $authUrl . "\n";
```

### Parámetros Opcionales

| Parámetro | Descripción |
|-----------|-------------|
| `prompt` | Controla el comportamiento de la pantalla de autorización |
| `login_hint` | Sugiere un email para el login |
| `max_age` | Tiempo máximo de validez de la sesión |

## 9. Ejemplo de Página de Autorización

Aquí tienes un ejemplo de una página completa de autorización:

```php
<?php
// authorization.php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;
use Tepuilabs\MeliServices\MeliScopes;
use Tepuilabs\MeliServices\MeliSites;

require 'vendor/autoload.php';

session_start();

// Configuración
$clientId = 'tu_client_id';
$clientSecret = 'tu_client_secret';
$redirectUri = 'http://localhost:9000/callback';

// Generar PKCE y State
$pkce = MeliConfig::generatePkce();
$state = MeliConfig::generateState();

$_SESSION['code_verifier'] = $pkce['code_verifier'];
$_SESSION['state'] = $state;

// Crear configuración
$config = MeliConfig::forAuthorization(
    clientId: $clientId,
    clientSecret: $clientSecret,
    redirectUri: $redirectUri,
    codeVerifier: $pkce['code_verifier'],
    codeChallenge: $pkce['code_challenge'],
    state: $state,
    scopes: MeliScopes::getOfflineAccess()
);

$meli = new MeliServices($config);

// Generar URLs para todos los sitios
$sites = MeliSites::getAll();
$authUrls = [];

foreach ($sites as $siteId => $siteInfo) {
    $authUrls[$siteId] = [
        'name' => $siteInfo['name'],
        'flag' => $siteInfo['flag'],
        'url' => $meli->getAuthorizationUrl($siteId)
    ];
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Autorizar con Mercado Libre</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .site-card {
            border: 1px solid #ddd;
            padding: 20px;
            margin: 10px 0;
            border-radius: 8px;
        }
        .auth-button {
            background: #00a650;
            color: white;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            display: inline-block;
        }
    </style>
</head>
<body>
    <h1>🔐 Autorizar con Mercado Libre</h1>
    <p>Selecciona tu país para continuar:</p>

    <?php foreach ($authUrls as $siteId => $info): ?>
        <div class="site-card">
            <h3><?= $info['flag'] ?> <?= $info['name'] ?></h3>
            <a href="<?= htmlspecialchars($info['url']) ?>" class="auth-button">
                Autorizar con Mercado Libre
            </a>
        </div>
    <?php endforeach; ?>

    <div style="margin-top: 30px; padding: 20px; background: #f5f5f5; border-radius: 8px;">
        <h3>📋 Información de Seguridad</h3>
        <ul>
            <li><strong>PKCE:</strong> Habilitado para mayor seguridad</li>
            <li><strong>State:</strong> <?= substr($state, 0, 20) ?>...</li>
            <li><strong>Scopes:</strong> <?= $config->getScopesString() ?></li>
            <li><strong>Redirect URI:</strong> <?= $redirectUri ?></li>
        </ul>
    </div>
</body>
</html>
```

## Resumen

En este capítulo has aprendido:

- ✅ Qué es PKCE y por qué es importante
- ✅ Cómo generar code verifier y challenge
- ✅ Cómo crear URLs de autorización seguras
- ✅ Soporte para múltiples sitios de Mercado Libre
- ✅ Validación de state para prevenir CSRF
- ✅ Manejo de errores de OAuth
- ✅ Parámetros adicionales disponibles
- ✅ Ejemplo completo de página de autorización

## Próximos Pasos

- [03. Intercambio de Tokens](./03-intercambio-tokens.md)
- [04. Refresh Tokens](./04-refresh-tokens.md)
- [05. Llamadas a la API](./05-llamadas-api.md)
- [06. Gestión de Aplicaciones](./06-gestion-aplicaciones.md)
