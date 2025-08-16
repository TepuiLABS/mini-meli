# 05. Llamadas a la API

## Introducción

Una vez que tienes un access token válido, puedes hacer llamadas a la API de Mercado Libre. En este capítulo aprenderás cómo usar la librería `mini-meli` para interactuar con todos los endpoints disponibles.

## Métodos Disponibles

La librería proporciona métodos para todos los verbos HTTP:

- `get()` - Solicitudes GET
- `post()` - Solicitudes POST
- `put()` - Solicitudes PUT
- `delete()` - Solicitudes DELETE
- `apiCall()` - Método genérico para cualquier HTTP

## 1. Configuración Inicial

Antes de hacer llamadas, necesitas configurar el servicio:

```php
<?php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;

require 'vendor/autoload.php';

session_start();

// Verificar que tenemos un access token
if (!isset($_SESSION['access_token'])) {
    die("❌ No hay access token disponible");
}

$accessToken = $_SESSION['access_token'];

// Crear configuración para llamadas a la API
$config = MeliConfig::forAuthorization(
    clientId: 'tu_client_id',
    clientSecret: 'tu_client_secret',
    redirectUri: 'http://localhost:9000/callback'
);

$meli = new MeliServices($config);
```

## 2. Llamadas GET Básicas

### Obtener Información del Usuario

```php
<?php

try {
    // Obtener perfil del usuario autenticado
    $userProfile = $meli->get('/users/me', $accessToken);

    echo "✅ Perfil obtenido:\n";
    echo "ID: " . $userProfile['id'] . "\n";
    echo "Nickname: " . $userProfile['nickname'] . "\n";
    echo "Email: " . $userProfile['email'] . "\n";
    echo "First Name: " . $userProfile['first_name'] . "\n";
    echo "Last Name: " . $userProfile['last_name'] . "\n";

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

### Obtener Publicaciones del Usuario

```php
<?php

try {
    $userId = $_SESSION['user_id'];

    // Obtener publicaciones del usuario
    $items = $meli->get("/users/{$userId}/items/search", $accessToken);

    echo "✅ Publicaciones obtenidas:\n";
    echo "Total: " . $items['paging']['total'] . "\n";
    echo "Página actual: " . $items['paging']['offset'] . "\n";
    echo "Límite: " . $items['paging']['limit'] . "\n";

    foreach ($items['results'] as $item) {
        echo "- " . $item['title'] . " (ID: " . $item['id'] . ")\n";
    }

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

### Obtener Categorías

```php
<?php

try {
    // Obtener categorías de Argentina
    $categories = $meli->get('/sites/MLA/categories', $accessToken);

    echo "✅ Categorías obtenidas:\n";
    foreach ($categories as $category) {
        echo "- " . $category['name'] . " (ID: " . $category['id'] . ")\n";
    }

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

## 3. Llamadas GET con Parámetros

### Búsqueda de Productos

```php
<?php

try {
    // Buscar productos con parámetros
    $searchParams = [
        'q' => 'iPhone',
        'limit' => 10,
        'offset' => 0,
        'sort' => 'price_asc'
    ];

    $searchResults = $meli->get('/sites/MLA/search?' . http_build_query($searchParams), $accessToken);

    echo "✅ Búsqueda realizada:\n";
    echo "Total encontrados: " . $searchResults['paging']['total'] . "\n";

    foreach ($searchResults['results'] as $item) {
        echo "- " . $item['title'] . " - $" . $item['price'] . "\n";
    }

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

### Obtener Detalles de un Producto

```php
<?php

try {
    $itemId = 'MLA1234567890';

    // Obtener detalles completos de un producto
    $itemDetails = $meli->get("/items/{$itemId}", $accessToken);

    echo "✅ Detalles del producto:\n";
    echo "Título: " . $itemDetails['title'] . "\n";
    echo "Precio: $" . $itemDetails['price'] . "\n";
    echo "Condición: " . $itemDetails['condition'] . "\n";
    echo "Categoría: " . $itemDetails['category_id'] . "\n";
    echo "Vendedor: " . $itemDetails['seller_id'] . "\n";

    // Información de envío
    if (isset($itemDetails['shipping'])) {
        echo "Envío gratuito: " . ($itemDetails['shipping']['free_shipping'] ? 'Sí' : 'No') . "\n";
    }

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

## 4. Llamadas POST

### Crear una Publicación

```php
<?php

try {
    $itemData = [
        'title' => 'iPhone 13 Pro Max 256GB',
        'category_id' => 'MLA1055',
        'price' => 1500000,
        'currency_id' => 'ARS',
        'available_quantity' => 1,
        'buying_mode' => 'buy_it_now',
        'condition' => 'new',
        'description' => [
            'plain_text' => 'iPhone 13 Pro Max en perfecto estado, 256GB, color Sierra Blue'
        ],
        'pictures' => [
            [
                'source' => 'https://example.com/iphone1.jpg'
            ]
        ],
        'attributes' => [
            [
                'id' => 'BRAND',
                'value_name' => 'Apple'
            ],
            [
                'id' => 'MODEL',
                'value_name' => 'iPhone 13 Pro Max'
            ]
        ]
    ];

    $newItem = $meli->post('/items', $accessToken, $itemData);

    echo "✅ Publicación creada:\n";
    echo "ID: " . $newItem['id'] . "\n";
    echo "Título: " . $newItem['title'] . "\n";
    echo "Estado: " . $newItem['status'] . "\n";

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

### Hacer una Pregunta

```php
<?php

try {
    $itemId = 'MLA1234567890';

    $questionData = [
        'text' => '¿Tienes stock disponible?',
        'item_id' => $itemId
    ];

    $question = $meli->post('/questions', $accessToken, $questionData);

    echo "✅ Pregunta enviada:\n";
    echo "ID: " . $question['id'] . "\n";
    echo "Texto: " . $question['text'] . "\n";
    echo "Estado: " . $question['status'] . "\n";

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

## 5. Llamadas PUT

### Actualizar una Publicación

```php
<?php

try {
    $itemId = 'MLA1234567890';

    $updateData = [
        'title' => 'iPhone 13 Pro Max 256GB - PRECIO REDUCIDO',
        'price' => 1400000,
        'available_quantity' => 2
    ];

    $updatedItem = $meli->put("/items/{$itemId}", $accessToken, $updateData);

    echo "✅ Publicación actualizada:\n";
    echo "ID: " . $updatedItem['id'] . "\n";
    echo "Nuevo título: " . $updatedItem['title'] . "\n";
    echo "Nuevo precio: $" . $updatedItem['price'] . "\n";

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

### Actualizar Descripción

```php
<?php

try {
    $itemId = 'MLA1234567890';

    $descriptionData = [
        'plain_text' => 'iPhone 13 Pro Max en perfecto estado, 256GB, color Sierra Blue. Incluye cargador original y funda protectora.'
    ];

    $updatedDescription = $meli->put("/items/{$itemId}/description", $accessToken, $descriptionData);

    echo "✅ Descripción actualizada:\n";
    echo "ID: " . $updatedDescription['id'] . "\n";
    echo "Texto: " . $updatedDescription['plain_text'] . "\n";

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

## 6. Llamadas DELETE

### Eliminar una Publicación

```php
<?php

try {
    $itemId = 'MLA1234567890';

    $result = $meli->delete("/items/{$itemId}", $accessToken);

    echo "✅ Publicación eliminada:\n";
    echo "ID: " . $result['id'] . "\n";
    echo "Estado: " . $result['status'] . "\n";

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

### Eliminar una Pregunta

```php
<?php

try {
    $questionId = 'MLA1234567890';

    $result = $meli->delete("/questions/{$questionId}", $accessToken);

    echo "✅ Pregunta eliminada\n";

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

## 7. Método Genérico apiCall()

Para casos más específicos, puedes usar el método genérico:

```php
<?php

try {
    // Llamada GET personalizada
    $customGet = $meli->apiCall('/users/me/addresses', $accessToken, 'GET');

    // Llamada POST personalizada
    $customPost = $meli->apiCall('/items', $accessToken, 'POST', [
        'title' => 'Producto de prueba',
        'category_id' => 'MLA1055',
        'price' => 1000
    ]);

    // Llamada PUT personalizada
    $customPut = $meli->apiCall('/items/MLA1234567890', $accessToken, 'PUT', [
        'price' => 1500
    ]);

    // Llamada DELETE personalizada
    $customDelete = $meli->apiCall('/items/MLA1234567890', $accessToken, 'DELETE');

    echo "✅ Todas las llamadas personalizadas exitosas\n";

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

## 8. Manejo de Paginación

Para endpoints que devuelven resultados paginados:

```php
<?php

try {
    $userId = $_SESSION['user_id'];
    $allItems = [];
    $offset = 0;
    $limit = 50;

    do {
        // Obtener página de resultados
        $items = $meli->get("/users/{$userId}/items/search?offset={$offset}&limit={$limit}", $accessToken);

        // Agregar resultados a la lista
        $allItems = array_merge($allItems, $items['results']);

        // Actualizar offset para la siguiente página
        $offset += $limit;

        echo "Obtenidos " . count($items['results']) . " items (offset: {$offset})\n";

    } while (count($items['results']) === $limit);

    echo "✅ Total de publicaciones obtenidas: " . count($allItems) . "\n";

    // Mostrar algunas publicaciones
    foreach (array_slice($allItems, 0, 5) as $item) {
        echo "- " . $item['title'] . " (ID: " . $item['id'] . ")\n";
    }

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

## 9. Ejemplo de Clase API Manager

Crear una clase para manejar llamadas a la API de forma organizada:

```php
<?php
// ApiManager.php

use Tepuilabs\MeliServices\MeliServices;
use Tepuilabs\MeliServices\Exceptions\GenericException;

class ApiManager {
    private MeliServices $meli;
    private string $accessToken;

    public function __construct(MeliServices $meli, string $accessToken) {
        $this->meli = $meli;
        $this->accessToken = $accessToken;
    }

    public function getUserProfile(): array {
        return $this->meli->get('/users/me', $this->accessToken);
    }

    public function getUserItems(int $userId, int $limit = 50): array {
        return $this->meli->get("/users/{$userId}/items/search?limit={$limit}", $this->accessToken);
    }

    public function searchItems(string $query, array $params = []): array {
        $defaultParams = [
            'q' => $query,
            'limit' => 20,
            'offset' => 0
        ];

        $searchParams = array_merge($defaultParams, $params);
        $queryString = http_build_query($searchParams);

        return $this->meli->get("/sites/MLA/search?{$queryString}", $this->accessToken);
    }

    public function getItemDetails(string $itemId): array {
        return $this->meli->get("/items/{$itemId}", $this->accessToken);
    }

    public function createItem(array $itemData): array {
        return $this->meli->post('/items', $this->accessToken, $itemData);
    }

    public function updateItem(string $itemId, array $updateData): array {
        return $this->meli->put("/items/{$itemId}", $this->accessToken, $updateData);
    }

    public function deleteItem(string $itemId): array {
        return $this->meli->delete("/items/{$itemId}", $this->accessToken);
    }

    public function getCategories(): array {
        return $this->meli->get('/sites/MLA/categories', $this->accessToken);
    }

    public function getCurrencies(): array {
        return $this->meli->get('/currencies', $this->accessToken);
    }

    public function getAllUserItems(int $userId): array {
        $allItems = [];
        $offset = 0;
        $limit = 50;

        do {
            $items = $this->getUserItems($userId, $limit);
            $allItems = array_merge($allItems, $items['results']);
            $offset += $limit;
        } while (count($items['results']) === $limit);

        return $allItems;
    }
}

// Uso
$apiManager = new ApiManager($meli, $accessToken);

try {
    // Obtener perfil
    $profile = $apiManager->getUserProfile();
    echo "Usuario: " . $profile['nickname'] . "\n";

    // Obtener publicaciones
    $items = $apiManager->getAllUserItems($profile['id']);
    echo "Total de publicaciones: " . count($items) . "\n";

    // Buscar productos
    $searchResults = $apiManager->searchItems('iPhone', ['limit' => 10]);
    echo "Resultados de búsqueda: " . count($searchResults['results']) . "\n";

} catch (GenericException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```

## 10. Ejemplo de Dashboard Completo

Aquí tienes un ejemplo de dashboard que usa todas las funcionalidades:

```php
<?php
// dashboard.php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;
use Tepuilabs\MeliServices\Exceptions\GenericException;

require 'vendor/autoload.php';

session_start();

// Verificar autenticación
if (!isset($_SESSION['access_token'])) {
    header('Location: authorization.php');
    exit;
}

$accessToken = $_SESSION['access_token'];
$userId = $_SESSION['user_id'];

$config = MeliConfig::forAuthorization(
    clientId: 'tu_client_id',
    clientSecret: 'tu_client_secret',
    redirectUri: 'http://localhost:9000/callback'
);

$meli = new MeliServices($config);
$apiManager = new ApiManager($meli, $accessToken);

$profile = null;
$items = [];
$error = null;

try {
    $profile = $apiManager->getUserProfile();
    $items = $apiManager->getAllUserItems($userId);
} catch (GenericException $e) {
    $error = $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Mercado Libre API</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .dashboard { display: grid; grid-template-columns: 1fr 2fr; gap: 20px; }
        .card { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .item { border: 1px solid #ddd; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .error { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 8px; }
    </style>
</head>
<body>
    <h1>📊 Dashboard - Mercado Libre API</h1>

    <?php if ($error): ?>
        <div class="error">
            <h2>❌ Error</h2>
            <p><?= htmlspecialchars($error) ?></p>
        </div>
    <?php endif; ?>

    <div class="dashboard">
        <div>
            <div class="card">
                <h2>👤 Perfil del Usuario</h2>
                <?php if ($profile): ?>
                    <p><strong>ID:</strong> <?= $profile['id'] ?></p>
                    <p><strong>Nickname:</strong> <?= $profile['nickname'] ?></p>
                    <p><strong>Email:</strong> <?= $profile['email'] ?></p>
                    <p><strong>Nombre:</strong> <?= $profile['first_name'] ?> <?= $profile['last_name'] ?></p>
                <?php endif; ?>
            </div>

            <div class="card">
                <h2>📈 Estadísticas</h2>
                <p><strong>Total de publicaciones:</strong> <?= count($items) ?></p>
                <p><strong>Token válido hasta:</strong> <?= date('Y-m-d H:i:s', time() + $_SESSION['expires_in']) ?></p>
            </div>
        </div>

        <div>
            <div class="card">
                <h2>📦 Mis Publicaciones</h2>
                <?php if (empty($items)): ?>
                    <p>No tienes publicaciones activas.</p>
                <?php else: ?>
                    <?php foreach (array_slice($items, 0, 10) as $item): ?>
                        <div class="item">
                            <h3><?= htmlspecialchars($item['title']) ?></h3>
                            <p><strong>ID:</strong> <?= $item['id'] ?></p>
                            <p><strong>Precio:</strong> $<?= $item['price'] ?></p>
                            <p><strong>Estado:</strong> <?= $item['status'] ?></p>
                            <p><strong>Condición:</strong> <?= $item['condition'] ?></p>
                        </div>
                    <?php endforeach; ?>

                    <?php if (count($items) > 10): ?>
                        <p><em>Mostrando 10 de <?= count($items) ?> publicaciones</em></p>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div style="margin-top: 20px;">
        <a href="refresh.php">🔄 Renovar Token</a> |
        <a href="?logout=1">🚪 Cerrar Sesión</a>
    </div>
</body>
</html>
```

## Resumen

En este capítulo has aprendido:

- ✅ Cómo hacer llamadas GET, POST, PUT y DELETE
- ✅ Uso de parámetros en las llamadas
- ✅ Manejo de paginación
- ✅ Creación de publicaciones
- ✅ Actualización y eliminación de datos
- ✅ Clase ApiManager para organización
- ✅ Dashboard completo de ejemplo
- ✅ Manejo de errores en llamadas API

## Próximos Pasos

- [06. Gestión de Aplicaciones](./06-gestion-aplicaciones.md)
- [07. Manejo de Errores Avanzado](./07-manejo-errores-avanzado.md)
- [08. Seguridad y Mejores Prácticas](./08-seguridad-mejores-practicas.md)
- [09. Casos de Uso Avanzados](./09-casos-uso-avanzados.md)
