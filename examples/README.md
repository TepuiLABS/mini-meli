# 📚 Documentación de Ejemplos - mini-meli

Bienvenido a la documentación completa de la librería `mini-meli`. Esta guía te llevará desde los conceptos básicos hasta casos de uso avanzados, con ejemplos prácticos y explicaciones detalladas.

## 🎯 ¿Qué es mini-meli?

`mini-meli` es una librería PHP moderna y robusta para interactuar con la API de Mercado Libre. Incluye soporte completo para:

- ✅ **OAuth 2.0 PKCE** - Autenticación segura
- ✅ **Refresh Tokens** - Renovación automática de tokens
- ✅ **Multi-Site Support** - Soporte para todos los países
- ✅ **App Management** - Gestión de aplicaciones
- ✅ **Error Handling** - Manejo robusto de errores
- ✅ **Type Safety** - PHP 8.3+ con tipos estrictos

## 📖 Guía de Aprendizaje

### 🚀 Nivel Básico

1. **[01. Configuración Básica](./01-configuracion-basica.md)**
   - Instalación y configuración inicial
   - Diferentes formas de crear configuración
   - Validación de parámetros
   - Scopes y permisos

2. **[02. Autenticación OAuth 2.0 PKCE](./02-autenticacion-oauth-pkce.md)**
   - Flujo completo de autenticación
   - Generación de PKCE y state
   - URLs de autorización
   - Validación de seguridad

3. **[03. Intercambio de Tokens](./03-intercambio-tokens.md)**
   - Procesamiento de callbacks
   - Intercambio de código por token
   - Almacenamiento seguro
   - Middleware de autenticación

### 🔄 Nivel Intermedio

4. **[04. Refresh Tokens](./04-refresh-tokens.md)**
   - Renovación automática de tokens
   - Manejo de expiración
   - Middleware de renovación
   - Clase TokenManager

5. **[05. Llamadas a la API](./05-llamadas-api.md)**
   - Métodos GET, POST, PUT, DELETE
   - Manejo de paginación
   - Creación de publicaciones
   - Dashboard completo

### 🏗️ Nivel Avanzado

6. **[06. Gestión de Aplicaciones](./06-gestion-aplicaciones.md)**
   - Detalles de aplicación
   - Usuarios autorizados
   - Revocación de permisos
   - Gestión de grants

7. **[07. Manejo de Errores Avanzado](./07-manejo-errores-avanzado.md)**
   - Tipos de errores específicos
   - Estrategias de retry
   - Logging y monitoreo
   - Fallbacks

8. **[08. Seguridad y Mejores Prácticas](./08-seguridad-mejores-practicas.md)**
   - Almacenamiento seguro de tokens
   - Validación de entrada
   - Protección CSRF
   - Auditoría de seguridad

9. **[09. Casos de Uso Avanzados](./09-casos-uso-avanzados.md)**
   - Webhooks
   - Procesamiento en lote
   - Caché y optimización
   - Integración con frameworks

## 🛠️ Requisitos del Sistema

- **PHP**: 8.3 o superior
- **Composer**: Para gestión de dependencias
- **Extensiones PHP**: `curl`, `json`, `openssl`
- **Aplicación Mercado Libre**: Registrada en [Mercado Libre Developers](https://developers.mercadolibre.com)

## 📦 Instalación Rápida

```bash
# Instalar la librería
composer require tepuilabs/mini-meli

# Crear archivo de configuración
cp .env.example .env

# Editar configuración
nano .env
```

## 🔧 Configuración Mínima

```php
<?php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;

require 'vendor/autoload.php';

// Configuración básica
$config = MeliConfig::fromArray([
    'client_id' => 'tu_client_id',
    'client_secret' => 'tu_client_secret',
    'redirect_uri' => 'http://localhost:9000/callback'
]);

$meli = new MeliServices($config);
```

## 🌍 Sitios Soportados

| País | Código | Dominio | Bandera |
|------|--------|---------|---------|
| Argentina | MLA | ar | 🇦🇷 |
| Brasil | MLB | br | 🇧🇷 |
| México | MLM | mx | 🇲🇽 |
| Chile | MLC | cl | 🇨🇱 |
| Colombia | MCO | co | 🇨🇴 |
| Perú | MPE | pe | 🇵🇪 |
| Uruguay | MLU | uy | 🇺🇾 |
| Venezuela | MLV | ve | 🇻🇪 |

## 🔐 Scopes Disponibles

- **`read`** - Permisos de solo lectura
- **`write`** - Permisos de lectura y escritura
- **`offline_access`** - Incluye refresh tokens

## 📊 Ejemplos de Uso

### Autenticación Básica

```php
// Generar URL de autorización
$authUrl = $meli->getAuthorizationUrl('MLA');

// Intercambiar código por token
$response = $meli->generateAccessToken();

// Hacer llamada a la API
$profile = $meli->get('/users/me', $response->getAccessToken());
```

### Renovación de Token

```php
// Renovar token automáticamente
$response = $meli->refreshAccessToken($refreshToken);

// Verificar expiración
if ($timeRemaining < 600) {
    $meli->refreshAccessToken($refreshToken);
}
```

### Llamadas a la API

```php
// Obtener publicaciones del usuario
$items = $meli->get("/users/{$userId}/items/search", $accessToken);

// Crear nueva publicación
$newItem = $meli->post('/items', $accessToken, $itemData);

// Actualizar publicación
$updatedItem = $meli->put("/items/{$itemId}", $accessToken, $updateData);
```

## 🚨 Manejo de Errores

```php
try {
    $response = $meli->generateAccessToken();
} catch (GenericException $e) {
    switch ($e->getCode()) {
        case 400:
            echo "Error de parámetros: " . $e->getMessage();
            break;
        case 401:
            echo "Token inválido: " . $e->getMessage();
            break;
        case 429:
            echo "Demasiadas solicitudes: " . $e->getMessage();
            break;
        default:
            echo "Error desconocido: " . $e->getMessage();
    }
}
```

## 📈 Características Principales

### 🔒 Seguridad
- **PKCE** - Proof Key for Code Exchange
- **State Validation** - Protección CSRF
- **Token Encryption** - Almacenamiento seguro
- **Input Validation** - Validación de entrada

### ⚡ Rendimiento
- **HTTP/2 Support** - Conexiones optimizadas
- **Connection Pooling** - Reutilización de conexiones
- **Timeout Handling** - Manejo de timeouts
- **Retry Logic** - Reintentos automáticos

### 🛠️ Desarrollo
- **Type Safety** - Tipos estrictos de PHP 8.3+
- **Named Arguments** - Argumentos nombrados
- **Exception Handling** - Manejo robusto de errores
- **Comprehensive Logging** - Logging detallado

## 🤝 Contribuir

¿Encontraste un error o quieres mejorar la documentación?

1. **Fork** el repositorio
2. **Crea** una rama para tu feature
3. **Commit** tus cambios
4. **Push** a la rama
5. **Abre** un Pull Request

## 📞 Soporte

- **Documentación**: [GitHub Wiki](https://github.com/tepuilabs/mini-meli/wiki)
- **Issues**: [GitHub Issues](https://github.com/tepuilabs/mini-meli/issues)
- **Discussions**: [GitHub Discussions](https://github.com/tepuilabs/mini-meli/discussions)

## 📄 Licencia

Este proyecto está bajo la licencia MIT. Ver el archivo [LICENSE](../LICENSE.md) para más detalles.

## 🙏 Agradecimientos

- **Mercado Libre** por proporcionar una API excelente
- **Comunidad PHP** por las mejores prácticas
- **Contribuidores** que han ayudado a mejorar la librería

---

**¿Listo para comenzar?** 🚀

Empieza con [01. Configuración Básica](./01-configuracion-basica.md) y construye tu primera integración con Mercado Libre.
