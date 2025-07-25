# mini-meli

[![Latest Version on Packagist](https://img.shields.io/packagist/v/tepuilabs/mini-meli.svg?style=flat-square)](https://packagist.org/packages/tepuilabs/mini-meli)
[![Total Downloads](https://img.shields.io/packagist/dt/tepuilabs/mini-meli.svg?style=flat-square)](https://packagist.org/packages/tepuilabs/mini-meli)
[![PHP Version](https://img.shields.io/packagist/php-v/tepuilabs/mini-meli.svg?style=flat-square)](https://packagist.org/packages/tepuilabs/mini-meli)

<p align="center">
	<img src="carbon_new.png" width="1028">
</p>

Genera access token de Mercado Libre con las últimas funcionalidades de PHP 8.3.

## Características

- ✅ **PHP 8.3+** - Aprovecha las últimas funcionalidades del lenguaje
- ✅ **Type Safety** - Tipado estricto y union types
- ✅ **Readonly Properties** - Inmutabilidad donde sea apropiado
- ✅ **Match Expressions** - Lógica más clara y eficiente
- ✅ **Named Arguments** - Mejor legibilidad del código
- ✅ **First-class Callable Syntax** - Sintaxis moderna para callbacks
- ✅ **Improved Error Handling** - Manejo de errores más específico
- ✅ **Backward Compatibility** - Compatible con versiones anteriores

## Instalación

```bash
composer require tepuilabs/mini-meli
```

## Configuración

### Variables de Entorno

Agrega en tu archivo de configuración:

```env
GRANT_TYPE=authorization_code
CLIENT_ID=tu_client_id
CLIENT_SECRET=tu_client_secret
REDIRECT_URL=http://localhost:9000
```

> [!NOTE]
> Estos datos los debes configurar en Mercado Libre cuando crees una aplicación. Solo necesitas el client_id y client_secret.

## Uso

### Método Moderno (Recomendado)

```php
<?php

use Tepuilabs\MeliServices\MeliServices;

require 'vendor/autoload.php';

// Crear desde variables de entorno
$meli = MeliServices::fromEnvironment();
$response = $meli->generateAccessToken();

// Acceder a los datos de la respuesta
echo $response->getAccessToken();
echo $response->getRefreshToken();
echo $response->getExpiresIn();

// O convertir a array
$data = $response->toArray();
```

### Método con Configuración Manual

```php
<?php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;

require 'vendor/autoload.php';

$config = new MeliConfig(
    clientId: 'tu_client_id',
    clientSecret: 'tu_client_secret',
    code: $_GET['code'], // desde la URL
    redirectUri: 'http://localhost:9000'
);

$meli = new MeliServices($config);
$response = $meli->generateAccessToken();
```

### Método Legacy (Compatibilidad)

```php
<?php

use Tepuilabs\MeliServices\MeliServices;

require 'vendor/autoload.php';

$params = [
    'grant_type' => 'authorization_code',
    'client_id' => 'tu_client_id',
    'code' => $_GET['code'], // desde la URL
    'client_secret' => 'tu_client_secret',
    'redirect_uri' => 'http://localhost:9000'
];

$response = (new MeliServices($params))->generateAccessTokenArray();
```

## API Reference

### MeliServices

#### Métodos Estáticos

- `fromArray(array $params): self` - Crear desde array
- `fromEnvironment(): self` - Crear desde variables de entorno

#### Métodos de Instancia

- `generateAccessToken(): MeliResponse` - Generar token (nuevo)
- `generateAccessTokenArray(): array` - Generar token (legacy)
- `getConfig(): MeliConfig` - Obtener configuración
- `isValid(): bool` - Verificar si la configuración es válida

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

### MeliConfig

#### Métodos Estáticos

- `fromArray(array $params): self` - Crear desde array
- `fromEnvironment(): self` - Crear desde variables de entorno

#### Métodos de Instancia

- `toArray(): array` - Convertir a array
- `isValid(): bool` - Verificar si es válido

## Manejo de Errores

La librería incluye manejo de errores específico:

```php
try {
    $response = $meli->generateAccessToken();
} catch (GenericException $e) {
    echo "Error: " . $e->getMessage();
}
```

### Tipos de Error

- **400** - Solicitud inválida
- **401** - Credenciales inválidas
- **403** - Acceso denegado
- **404** - Endpoint no encontrado
- **429** - Demasiadas solicitudes
- **5xx** - Error del servidor

## Testing

```bash
# Ejecutar tests
composer test

# Ejecutar tests con coverage
composer test-coverage

# Formatear código
composer format
```

## Contribuir

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo [LICENSE.md](LICENSE.md) para más detalles.
