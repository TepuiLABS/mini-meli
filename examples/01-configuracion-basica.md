# 01. Configuración Básica

## Introducción

Este es el primer paso para comenzar a usar la librería `mini-meli`. Aprenderás cómo configurar la librería de diferentes maneras y validar que todo esté funcionando correctamente.

## Requisitos Previos

- PHP 8.3 o superior
- Composer instalado
- Una aplicación creada en Mercado Libre Developers

## Instalación

```bash
composer require tepuilabs/mini-meli
```

## 1. Configuración desde Array

La forma más directa de crear una configuración es usando un array con los parámetros necesarios. **Importante**: El parámetro `code` solo se usa cuando ya tienes un código de autorización (parte del flujo OAuth), no es necesario para comenzar.

### Configuración Básica (sin code)

```php
<?php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliScopes;

require 'vendor/autoload.php';

// Configuración básica para generar URLs de autorización
$config = MeliConfig::fromArray([
    'client_id' => 'tu_client_id_aqui',
    'client_secret' => 'tu_client_secret_aqui',
    'redirect_uri' => 'http://localhost:9000',
    'scopes' => MeliScopes::getDefault(), // read write
]);

// Verificar si la configuración es válida
if ($config->isValid()) {
    echo "✅ Configuración válida\n";
    echo "Client ID: " . $config->clientId . "\n";
    echo "Redirect URI: " . $config->redirectUri . "\n";
    echo "Scopes: " . $config->getScopesString() . "\n";
} else {
    echo "❌ Configuración inválida\n";
}
```

### Configuración con Code (para intercambio de tokens)

```php
<?php

// Esta configuración se usa DESPUÉS de recibir el code de Mercado Libre
$config = MeliConfig::fromArray([
    'client_id' => 'tu_client_id_aqui',
    'client_secret' => 'tu_client_secret_aqui',
    'code' => 'TG-1234567890abcdef', // Código recibido de Mercado Libre
    'redirect_uri' => 'http://localhost:9000',
    'scopes' => MeliScopes::getDefault(),
]);
```

### Parámetros Disponibles

| Parámetro | Tipo | Requerido | Descripción |
|-----------|------|-----------|-------------|
| `client_id` | string | ✅ | ID de tu aplicación en Mercado Libre |
| `client_secret` | string | ✅ | Secret de tu aplicación |
| `code` | string | ⚠️ | **Código de autorización** (solo para intercambio de tokens, NO necesario para comenzar) |
| `redirect_uri` | string | ⚠️ | URL de redirección configurada en tu app |
| `grant_type` | string | ❌ | Tipo de grant (default: 'authorization_code') |
| `scopes` | array/string | ❌ | Permisos solicitados |

## 2. Configuración desde Variables de Entorno

Para mayor seguridad, puedes usar variables de entorno:

```bash
# .env
CLIENT_ID=tu_client_id_aqui
CLIENT_SECRET=tu_client_secret_aqui
REDIRECT_URL=http://localhost:9000
SCOPES=read write offline_access
```

```php
<?php

use Tepuilabs\MeliServices\MeliConfig;

require 'vendor/autoload.php';

// Configuración desde variables de entorno
$config = MeliConfig::fromEnvironment();

echo "Client ID: " . $config->clientId . "\n";
echo "Redirect URI: " . $config->redirectUri . "\n";
echo "Scopes: " . $config->getScopesString() . "\n";
```

### Variables de Entorno Soportadas

| Variable | Descripción |
|----------|-------------|
| `CLIENT_ID` | ID de tu aplicación |
| `CLIENT_SECRET` | Secret de tu aplicación |
| `CODE` | Código de autorización |
| `REDIRECT_URL` | URL de redirección |
| `GRANT_TYPE` | Tipo de grant |
| `SCOPES` | Permisos (separados por espacios) |

## 3. ¿Cuándo usar cada tipo de configuración?

### 🔗 Para generar URLs de autorización (INICIO del flujo)

```php
<?php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliScopes;

require 'vendor/autoload.php';

// Configuración específica para autorización
$config = MeliConfig::forAuthorization(
    clientId: 'tu_client_id',
    clientSecret: 'tu_client_secret',
    redirectUri: 'http://localhost:9000',
    scopes: MeliScopes::getOfflineAccess() // Incluye refresh tokens
);

echo "✅ Configuración para autorización creada\n";
echo "Es para intercambio de tokens: " . ($config->isForTokenExchange() ? 'Sí' : 'No') . "\n";
```

### 🔄 Para intercambiar code por tokens (DESPUÉS de la autorización)

```php
<?php

// Esta configuración se usa cuando ya recibiste el 'code' de Mercado Libre
$code = $_GET['code']; // Ejemplo: TG-1234567890abcdef

$config = new MeliConfig(
    clientId: 'tu_client_id',
    clientSecret: 'tu_client_secret',
    code: $code, // El código que recibiste
    redirectUri: 'http://localhost:9000',
    scopes: MeliScopes::getOfflineAccess()
);

$meli = new MeliServices($config);
$response = $meli->generateAccessToken(); // Intercambia code por tokens
```

### 📋 Resumen de cuándo usar cada uno:

| Escenario | Método | ¿Necesitas `code`? | ¿Para qué? |
|-----------|--------|-------------------|------------|
| **Generar URL de autorización** | `MeliConfig::forAuthorization()` | ❌ NO | Crear link para que el usuario autorice |
| **Intercambiar code por tokens** | `new MeliConfig()` con `code` | ✅ SÍ | Obtener access_token y refresh_token |
| **Hacer llamadas a la API** | `new MeliConfig()` sin `code` | ❌ NO | Usar access_token existente |

## 4. Validación de Configuración

La librería incluye validación automática de parámetros:

```php
<?php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\Exceptions\GenericException;

require 'vendor/autoload.php';

try {
    // Configuración válida
    $validConfig = MeliConfig::fromArray([
        'client_id' => 'valid_id',
        'client_secret' => 'valid_secret',
        'code' => 'valid_code',
        'redirect_uri' => 'http://localhost:9000',
    ]);

    echo "✅ Configuración válida\n";

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}

try {
    // Configuración inválida - URL mal formada
    $invalidConfig = MeliConfig::fromArray([
        'client_id' => 'valid_id',
        'client_secret' => 'valid_secret',
        'redirect_uri' => 'invalid-url',
    ]);

} catch (GenericException $e) {
    echo "❌ Error esperado: " . $e->getMessage() . "\n";
}

// 💡 Nota importante: El parámetro 'code' solo es necesario cuando vas a intercambiar
// un código de autorización por tokens. Para comenzar el flujo OAuth, NO lo necesitas.

## 5. Scopes y Permisos

La librería incluye constantes para los scopes disponibles:

```php
<?php

use Tepuilabs\MeliServices\MeliScopes;

require 'vendor/autoload.php';

// Scopes disponibles
echo "Scopes disponibles:\n";
echo "- " . MeliScopes::READ . " (Solo lectura)\n";
echo "- " . MeliScopes::WRITE . " (Lectura y escritura)\n";
echo "- " . MeliScopes::OFFLINE_ACCESS . " (Incluye refresh tokens)\n";

// Obtener scopes predefinidos
$defaultScopes = MeliScopes::getDefault();
echo "Scopes por defecto: " . implode(', ', $defaultScopes) . "\n";

$offlineScopes = MeliScopes::getOfflineAccess();
echo "Scopes con offline access: " . implode(', ', $offlineScopes) . "\n";

// Validar scopes
$testScopes = ['read', 'write', 'offline_access'];
if (MeliScopes::validateScopes($testScopes)) {
    echo "✅ Scopes válidos\n";
} else {
    echo "❌ Scopes inválidos\n";
}
```

## 6. Crear MeliServices

Una vez que tienes la configuración, puedes crear una instancia de `MeliServices`:

```php
<?php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;

require 'vendor/autoload.php';

// Crear configuración
$config = MeliConfig::fromArray([
    'client_id' => 'tu_client_id',
    'client_secret' => 'tu_client_secret',
    'redirect_uri' => 'http://localhost:9000',
]);

// Crear servicio
$meli = new MeliServices($config);

// Verificar si es válido
if ($meli->isValid()) {
    echo "✅ Servicio creado exitosamente\n";
    echo "Configuración válida: " . ($meli->getConfig()->isValid() ? 'Sí' : 'No') . "\n";
} else {
    echo "❌ Error en la configuración\n";
}
```

## 7. Métodos de Creación Rápida

La librería también ofrece métodos estáticos para crear servicios rápidamente:

```php
<?php

use Tepuilabs\MeliServices\MeliServices;

require 'vendor/autoload.php';

// Desde array
$meliFromArray = MeliServices::fromArray([
    'client_id' => 'tu_client_id',
    'client_secret' => 'tu_client_secret',
    'redirect_uri' => 'http://localhost:9000',
]);

// Desde variables de entorno
$meliFromEnv = MeliServices::fromEnvironment();

echo "Servicios creados: " . ($meliFromArray->isValid() ? 'Array OK' : 'Array Error') . "\n";
echo "Servicios creados: " . ($meliFromEnv->isValid() ? 'Env OK' : 'Env Error') . "\n";
```

## Resumen

En este primer paso has aprendido:

- ✅ Cómo instalar la librería
- ✅ Diferentes formas de crear configuración
- ✅ Validación automática de parámetros
- ✅ Uso de scopes y permisos
- ✅ Creación de instancias de MeliServices
- ✅ Métodos de creación rápida

## Próximos Pasos

- [02. Autenticación OAuth 2.0 PKCE](./02-autenticacion-oauth-pkce.md)
- [03. Intercambio de Tokens](./03-intercambio-tokens.md)
- [04. Refresh Tokens](./04-refresh-tokens.md)
- [05. Llamadas a la API](./05-llamadas-api.md)
