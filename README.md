# mini-meli

[![Latest Version on Packagist](https://img.shields.io/packagist/v/tepuilabs/mini-meli.svg?style=flat-square)](https://packagist.org/packages/tepuilabs/mini-meli)
[![Total Downloads](https://img.shields.io/packagist/dt/tepuilabs/mini-meli.svg?style=flat-square)](https://packagist.org/packages/tepuilabs/mini-meli)
[![PHP Version](https://img.shields.io/packagist/php-v/tepuilabs/mini-meli.svg?style=flat-square)](https://packagist.org/packages/tepuilabs/mini-meli)

<p align="center">
	<img src="carbon_new.png" width="1028">
</p>

Librería completa para Mercado Libre con OAuth 2.0 PKCE, refresh tokens y gestión de aplicaciones. Implementa todas las mejores prácticas de seguridad y funcionalidades de la API oficial.

## 🚀 Características

- ✅ **OAuth 2.0 PKCE** - Autenticación segura con Proof Key for Code Exchange
- ✅ **Refresh Tokens** - Renovación automática de tokens con offline_access
- ✅ **Multi-Site Support** - Soporte para todos los sitios de Mercado Libre
- ✅ **App Management** - Gestión completa de aplicaciones y permisos
- ✅ **Security First** - Validación robusta y protección CSRF
- ✅ **PHP 8.3+** - Aprovecha las últimas funcionalidades del lenguaje
- ✅ **Type Safety** - Tipado estricto y union types
- ✅ **Readonly Properties** - Inmutabilidad donde sea apropiado
- ✅ **Match Expressions** - Lógica más clara y eficiente
- ✅ **Named Arguments** - Mejor legibilidad del código
- ✅ **First-class Callable Syntax** - Sintaxis moderna para callbacks
- ✅ **Improved Error Handling** - Manejo de errores más específico
- ✅ **Backward Compatibility** - Compatible con versiones anteriores

## 📦 Instalación

```bash
composer require tepuilabs/mini-meli
```

## ⚙️ Configuración

### Variables de Entorno

Agrega en tu archivo de configuración:

```env
GRANT_TYPE=authorization_code
CLIENT_ID=tu_client_id
CLIENT_SECRET=tu_client_secret
REDIRECT_URL=http://localhost:9000
SCOPES=read write offline_access
```

> [!NOTE]
> Estos datos los debes configurar en Mercado Libre cuando crees una aplicación. Solo necesitas el client_id y client_secret.

## 🔐 Uso

### 1. Autenticación OAuth 2.0 PKCE

```php
<?php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;
use Tepuilabs\MeliServices\MeliScopes;

require 'vendor/autoload.php';

// Generar PKCE y state
$pkce = MeliConfig::generatePkce();
$state = MeliConfig::generateState();

// Crear configuración
$config = MeliConfig::forAuthorization(
    clientId: 'tu_client_id',
    clientSecret: 'tu_client_secret',
    redirectUri: 'http://localhost:9000',
    codeVerifier: $pkce['code_verifier'],
    codeChallenge: $pkce['code_challenge'],
    state: $state,
    scopes: MeliScopes::getOfflineAccess() // Incluye refresh tokens
);

$meli = new MeliServices($config);

// Generar URL de autorización
$authUrl = $meli->getAuthorizationUrl('MLA'); // Argentina
echo "Ve a: {$authUrl}";
```

### 2. Intercambio de Código por Token

```php
// En tu callback
$code = $_GET['code'] ?? '';
$state = $_GET['state'] ?? '';

// Verificar state para seguridad
if ($state !== $savedState) {
    throw new Exception("State no coincide");
}

$config = new MeliConfig(
    clientId: 'tu_client_id',
    clientSecret: 'tu_client_secret',
    code: $code,
    redirectUri: 'http://localhost:9000',
    codeVerifier: $savedCodeVerifier // De la sesión
);

$meli = new MeliServices($config);
$response = $meli->generateAccessToken();

// Guardar tokens
$accessToken = $response->getAccessToken();
$refreshToken = $response->getRefreshToken();
$userId = $response->getUserId();
```

### 3. Refresh Tokens

```php
// Renovar token cuando expire
$response = $meli->refreshAccessToken($refreshToken);

// Actualizar tokens
$newAccessToken = $response->getAccessToken();
$newRefreshToken = $response->getRefreshToken(); // Siempre nuevo
```

### 4. Llamadas a la API

```php
// Crear instancia para API calls
$config = MeliConfig::forAuthorization(
    clientId: 'tu_client_id',
    clientSecret: 'tu_client_secret',
    redirectUri: 'http://localhost:9000'
);
$meli = new MeliServices($config);

// Hacer llamadas
$userProfile = $meli->get('/users/me', $accessToken);
$userItems = $meli->get("/users/{$userId}/items/search", $accessToken);
$categories = $meli->get('/sites/MLA/categories', $accessToken);
```

### 5. Gestión de Aplicaciones

```php
// Obtener detalles de la aplicación
$appDetails = $meli->getApplicationDetails($accessToken, $appId);

// Obtener aplicaciones autorizadas por el usuario
$userApps = $meli->getUserApplications($accessToken, $userId);

// Obtener usuarios que dieron permisos a tu app
$appGrants = $meli->getApplicationGrants($accessToken, $appId);

// Revocar autorización de un usuario
$result = $meli->revokeUserAuthorization($accessToken, $userId, $appId);
```

## 🌍 Sitios Soportados

La librería soporta todos los sitios de Mercado Libre:

```php
use Tepuilabs\MeliServices\MeliSites;

// Sitios disponibles
MeliSites::MLA; // Argentina
MeliSites::MLB; // Brasil
MeliSites::MLM; // México
MeliSites::MLC; // Chile
MeliSites::MCO; // Colombia
MeliSites::MPE; // Perú
MeliSites::MLU; // Uruguay
MeliSites::MLV; // Venezuela

// Obtener información del sitio
$siteInfo = MeliSites::getSite('MLA');
$domain = MeliSites::getDomain('MLA');
$name = MeliSites::getName('MLA');
$flag = MeliSites::getFlag('MLA');
```

## 🔑 Scopes y Permisos

```php
use Tepuilabs\MeliServices\MeliScopes;

// Scopes disponibles
MeliScopes::READ;           // Solo lectura
MeliScopes::WRITE;          // Lectura y escritura
MeliScopes::OFFLINE_ACCESS; // Incluye refresh tokens

// Obtener scopes predefinidos
$defaultScopes = MeliScopes::getDefault();        // read write
$offlineScopes = MeliScopes::getOfflineAccess();  // read write offline_access

// Validar scopes
$isValid = MeliScopes::isValid('read');
$hasOffline = MeliScopes::hasOfflineAccess($scopes);
$hasRead = MeliScopes::hasRead($scopes);
$hasWrite = MeliScopes::hasWrite($scopes);
```

## 🛡️ Seguridad

### PKCE (Proof Key for Code Exchange)

La librería implementa PKCE para prevenir ataques de interceptación de código:

```php
// Generación automática
$pkce = MeliConfig::generatePkce();
// code_verifier: string aleatorio de 32 bytes
// code_challenge: hash SHA-256 del verifier, base64url encoded
```

### State Protection

Protección CSRF con parámetros state aleatorios:

```php
$state = MeliConfig::generateState(); // 16 bytes aleatorios
```

### Validación Robusta

```php
// Validación automática de parámetros
$config = new MeliConfig(
    clientId: $clientId,
    clientSecret: $clientSecret,
    code: $code,
    redirectUri: $redirectUri,
    codeVerifier: $codeVerifier
);

if (!$config->isValid()) {
    throw new Exception("Configuración inválida");
}
```

## 📚 API Reference

### MeliServices

#### Métodos Estáticos

- `fromArray(array $params): self` - Crear desde array
- `fromEnvironment(): self` - Crear desde variables de entorno

#### Métodos de Instancia

- `generateAccessToken(): MeliResponse` - Generar token
- `refreshAccessToken(string $refreshToken): MeliResponse` - Renovar token
- `getAuthorizationUrl(string $site, array $params = []): string` - Generar URL de autorización
- `get(string $endpoint, string $accessToken): array` - GET request
- `post(string $endpoint, string $accessToken, array $data = []): array` - POST request
- `put(string $endpoint, string $accessToken, array $data = []): array` - PUT request
- `delete(string $endpoint, string $accessToken): array` - DELETE request
- `getApplicationDetails(string $accessToken, string $appId): array` - Detalles de app
- `getUserApplications(string $accessToken, string $userId): array` - Apps del usuario
- `getApplicationGrants(string $accessToken, string $appId): array` - Usuarios conectados
- `revokeUserAuthorization(string $accessToken, string $userId, string $appId): array` - Revocar autorización

### MeliConfig

#### Métodos Estáticos

- `fromArray(array $params): self` - Crear desde array
- `fromEnvironment(): self` - Crear desde variables de entorno
- `forAuthorization(...): self` - Crear para URLs de autorización
- `generatePkce(): array` - Generar PKCE
- `generateState(): string` - Generar state

#### Métodos de Instancia

- `toArray(): array` - Convertir a array
- `isValid(): bool` - Verificar si es válido
- `hasPkce(): bool` - Verificar si tiene PKCE
- `hasState(): bool` - Verificar si tiene state
- `hasRefreshToken(): bool` - Verificar si tiene refresh token
- `isForTokenExchange(): bool` - Verificar si es para intercambio
- `getScopesString(): string` - Obtener scopes como string
- `hasOfflineAccess(): bool` - Verificar offline access
- `hasReadPermission(): bool` - Verificar permiso de lectura
- `hasWritePermission(): bool` - Verificar permiso de escritura

### MeliResponse

#### Propiedades

- `data: array` - Datos de la respuesta
- `statusCode: int` - Código de estado HTTP

#### Métodos

- `getAccessToken(): ?string` - Obtener access token
- `getRefreshToken(): ?string` - Obtener refresh token
- `getTokenType(): ?string` - Obtener tipo de token
- `getExpiresIn(): ?int` - Obtener tiempo de expiración
- `getScope(): ?string` - Obtener scope
- `getUserId(): ?int` - Obtener ID de usuario
- `hasAccessToken(): bool` - Verificar si tiene access token
- `hasRefreshToken(): bool` - Verificar si tiene refresh token
- `toArray(): array` - Convertir a array
- `toJson(): string` - Convertir a JSON
- `isSuccessful(): bool` - Verificar si la respuesta es exitosa
- `getErrorMessage(): ?string` - Obtener mensaje de error
- `getErrorDescription(): ?string` - Obtener descripción del error

### MeliScopes

#### Constantes

- `READ` - Permiso de lectura
- `WRITE` - Permiso de escritura
- `OFFLINE_ACCESS` - Permiso offline (refresh tokens)

#### Métodos Estáticos

- `getAll(): array` - Obtener todos los scopes
- `getDefault(): array` - Obtener scopes por defecto
- `getOfflineAccess(): array` - Obtener scopes con offline access
- `isValid(string $scope): bool` - Validar scope
- `validateScopes(array $scopes): bool` - Validar múltiples scopes
- `toString(array $scopes): string` - Convertir a string
- `toArray(string $scopes): array` - Convertir a array
- `hasOfflineAccess(array|string $scopes): bool` - Verificar offline access
- `hasRead(array|string $scopes): bool` - Verificar lectura
- `hasWrite(array|string $scopes): bool` - Verificar escritura

### MeliSites

#### Constantes

- `MLA` - Argentina
- `MLB` - Brasil
- `MLM` - México
- `MLC` - Chile
- `MCO` - Colombia
- `MPE` - Perú
- `MLU` - Uruguay
- `MLV` - Venezuela

#### Métodos Estáticos

- `getAll(): array` - Obtener todos los sitios
- `getSite(string $siteId): ?array` - Obtener información del sitio
- `getDomain(string $siteId): string` - Obtener dominio
- `getName(string $siteId): string` - Obtener nombre
- `getFlag(string $siteId): string` - Obtener bandera
- `isValid(string $siteId): bool` - Validar sitio
- `getAuthorizationUrl(string $siteId): string` - Obtener URL de autorización
- `getApiUrl(): string` - Obtener URL base de la API
- `getOAuthTokenEndpoint(): string` - Obtener endpoint de tokens

## 🚨 Manejo de Errores

La librería incluye manejo de errores específico:

```php
try {
    $response = $meli->generateAccessToken();
} catch (GenericException $e) {
    echo "Error: " . $e->getMessage();
    echo "Código: " . $e->getCode();
}
```

### Tipos de Error

- **400** - Solicitud inválida
- **401** - Credenciales inválidas
- **403** - Acceso denegado
- **404** - Endpoint no encontrado
- **429** - Demasiadas solicitudes
- **5xx** - Error del servidor

### Errores Específicos de OAuth

- **invalid_client** - Client ID o Secret inválidos
- **invalid_grant** - Código o refresh token inválido/expirado
- **invalid_scope** - Scope inválido
- **invalid_request** - Parámetros faltantes o inválidos
- **unsupported_grant_type** - Grant type no soportado
- **forbidden** - Acceso denegado
- **local_rate_limited** - Demasiadas solicitudes
- **unauthorized_client** - Cliente no autorizado
- **unauthorized_application** - Aplicación bloqueada

## 🧪 Testing

```bash
# Ejecutar tests
composer test

# Ejecutar tests con coverage
composer test-coverage

# Formatear código
composer format
```

## 📝 Ejemplo Completo

```php
<?php

use Tepuilabs\MeliServices\Exceptions\GenericException;
use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;
use Tepuilabs\MeliServices\MeliScopes;

require 'vendor/autoload.php';

session_start();

// Configuración
$clientId = 'tu_client_id';
$clientSecret = 'tu_client_secret';
$redirectUri = 'http://localhost:9000';

// Paso 1: Generar URL de autorización
if (!isset($_GET['code'])) {
    $pkce = MeliConfig::generatePkce();
    $state = MeliConfig::generateState();

    $_SESSION['code_verifier'] = $pkce['code_verifier'];
    $_SESSION['state'] = $state;

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
    $authUrl = $meli->getAuthorizationUrl('MLA');

    echo "Ve a: {$authUrl}";
    exit;
}

// Paso 2: Intercambiar código por token
try {
    $code = $_GET['code'];
    $state = $_GET['state'];

    // Verificar state
    if ($state !== $_SESSION['state']) {
        throw new Exception("State no coincide");
    }

    $config = new MeliConfig(
        clientId: $clientId,
        clientSecret: $clientSecret,
        code: $code,
        redirectUri: $redirectUri,
        codeVerifier: $_SESSION['code_verifier']
    );

    $meli = new MeliServices($config);
    $response = $meli->generateAccessToken();

    // Guardar tokens
    $_SESSION['access_token'] = $response->getAccessToken();
    $_SESSION['refresh_token'] = $response->getRefreshToken();
    $_SESSION['user_id'] = $response->getUserId();

    echo "¡Autenticación exitosa!";

} catch (GenericException $e) {
    echo "Error: " . $e->getMessage();
}
```

## 🤝 Contribuir

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo [LICENSE.md](LICENSE.md) para más detalles.

## 🔗 Enlaces Útiles

- [Documentación oficial de Mercado Libre](https://developers.mercadolibre.com.ar/es_ar/autenticacion-y-autorizacion)
- [Recomendaciones de seguridad](https://developers.mercadolibre.com.ar/es_ar/recomendaciones-de-autorizacion-y-token)
- [Gestión de aplicaciones](https://developers.mercadolibre.com.ar/es_ar/gestiona-tus-aplicaciones)
