# 06. Gestión de Aplicaciones

## Introducción

La librería `mini-meli` incluye funcionalidades avanzadas para gestionar aplicaciones de Mercado Libre. En este capítulo aprenderás cómo obtener detalles de tu aplicación, ver usuarios autorizados, gestionar permisos y revocar autorizaciones.

## Funcionalidades Disponibles

- **Detalles de Aplicación** - Información completa de tu app
- **Usuarios Autorizados** - Lista de usuarios que autorizaron tu app
- **Grants de Aplicación** - Usuarios conectados a tu aplicación
- **Revocación de Autorizaciones** - Revocar permisos de usuarios

## 1. Obtener Detalles de la Aplicación

### Información Básica de la App

```php
<?php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;
use Tepuilabs\MeliServices\Exceptions\GenericException;

require 'vendor/autoload.php';

session_start();

// Verificar autenticación
if (!isset($_SESSION['access_token'])) {
    die("❌ No hay access token disponible");
}

$accessToken = $_SESSION['access_token'];
$clientId = 'tu_client_id';

// Crear configuración
$config = MeliConfig::forAuthorization(
    clientId: $clientId,
    clientSecret: 'tu_client_secret',
    redirectUri: 'http://localhost:9000/callback'
);

$meli = new MeliServices($config);

try {
    // Obtener detalles de la aplicación
    $appDetails = $meli->getApplicationDetails($accessToken, $clientId);

    echo "✅ Detalles de la aplicación:\n";
    echo "ID: " . $appDetails['id'] . "\n";
    echo "Nombre: " . $appDetails['name'] . "\n";
    echo "Descripción: " . $appDetails['description'] . "\n";
    echo "URL: " . $appDetails['url'] . "\n";
    echo "Estado: " . $appDetails['status'] . "\n";

    if (isset($appDetails['created'])) {
        echo "Creada: " . date('Y-m-d H:i:s', strtotime($appDetails['created'])) . "\n";
    }

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

### Información Detallada de la App

```php
<?php

try {
    $appDetails = $meli->getApplicationDetails($accessToken, $clientId);

    echo "📱 Información Completa de la Aplicación:\n";
    echo "==========================================\n";

    // Información básica
    echo "🔹 Información Básica:\n";
    echo "   ID: " . $appDetails['id'] . "\n";
    echo "   Nombre: " . $appDetails['name'] . "\n";
    echo "   Descripción: " . $appDetails['description'] . "\n";
    echo "   URL: " . $appDetails['url'] . "\n";
    echo "   Estado: " . $appDetails['status'] . "\n";

    // Configuración OAuth
    if (isset($appDetails['oauth'])) {
        echo "\n🔹 Configuración OAuth:\n";
        echo "   Redirect URIs: " . implode(', ', $appDetails['oauth']['redirect_uris']) . "\n";
        echo "   Scopes: " . implode(', ', $appDetails['oauth']['scopes']) . "\n";
    }

    // Estadísticas
    if (isset($appDetails['stats'])) {
        echo "\n🔹 Estadísticas:\n";
        echo "   Usuarios autorizados: " . $appDetails['stats']['authorized_users'] . "\n";
        echo "   Llamadas API: " . $appDetails['stats']['api_calls'] . "\n";
    }

    // Configuración de webhooks
    if (isset($appDetails['webhooks'])) {
        echo "\n🔹 Webhooks:\n";
        foreach ($appDetails['webhooks'] as $webhook) {
            echo "   - " . $webhook['url'] . " (" . $webhook['status'] . ")\n";
        }
    }

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

## 2. Obtener Aplicaciones Autorizadas por Usuario

### Lista de Apps que el Usuario Autorizó

```php
<?php

try {
    $userId = $_SESSION['user_id'];

    // Obtener aplicaciones autorizadas por el usuario
    $userApps = $meli->getUserApplications($accessToken, $userId);

    echo "✅ Aplicaciones autorizadas por el usuario:\n";
    echo "Total: " . count($userApps) . "\n\n";

    foreach ($userApps as $app) {
        echo "📱 Aplicación: " . $app['name'] . "\n";
        echo "   ID: " . $app['id'] . "\n";
        echo "   Descripción: " . $app['description'] . "\n";
        echo "   URL: " . $app['url'] . "\n";
        echo "   Estado: " . $app['status'] . "\n";

        if (isset($app['authorized_date'])) {
            echo "   Autorizada: " . date('Y-m-d H:i:s', strtotime($app['authorized_date'])) . "\n";
        }

        if (isset($app['scopes'])) {
            echo "   Scopes: " . implode(', ', $app['scopes']) . "\n";
        }

        echo "\n";
    }

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

### Filtrar por Estado de Autorización

```php
<?php

try {
    $userId = $_SESSION['user_id'];
    $userApps = $meli->getUserApplications($accessToken, $userId);

    // Filtrar aplicaciones activas
    $activeApps = array_filter($userApps, function($app) {
        return $app['status'] === 'active';
    });

    // Filtrar aplicaciones inactivas
    $inactiveApps = array_filter($userApps, function($app) {
        return $app['status'] === 'inactive';
    });

    echo "📊 Estadísticas de Autorizaciones:\n";
    echo "==================================\n";
    echo "Total de aplicaciones: " . count($userApps) . "\n";
    echo "Aplicaciones activas: " . count($activeApps) . "\n";
    echo "Aplicaciones inactivas: " . count($inactiveApps) . "\n\n";

    if (!empty($activeApps)) {
        echo "✅ Aplicaciones Activas:\n";
        foreach ($activeApps as $app) {
            echo "   - " . $app['name'] . " (ID: " . $app['id'] . ")\n";
        }
        echo "\n";
    }

    if (!empty($inactiveApps)) {
        echo "⚠️ Aplicaciones Inactivas:\n";
        foreach ($inactiveApps as $app) {
            echo "   - " . $app['name'] . " (ID: " . $app['id'] . ")\n";
        }
        echo "\n";
    }

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

## 3. Obtener Grants de la Aplicación

### Usuarios Conectados a tu App

```php
<?php

try {
    // Obtener usuarios que autorizaron tu aplicación
    $appGrants = $meli->getApplicationGrants($accessToken, $clientId);

    echo "✅ Usuarios conectados a tu aplicación:\n";
    echo "Total: " . count($appGrants) . "\n\n";

    foreach ($appGrants as $grant) {
        echo "👤 Usuario: " . $grant['user_id'] . "\n";
        echo "   Nickname: " . $grant['nickname'] . "\n";
        echo "   Email: " . $grant['email'] . "\n";
        echo "   Estado: " . $grant['status'] . "\n";

        if (isset($grant['authorized_date'])) {
            echo "   Autorizado: " . date('Y-m-d H:i:s', strtotime($grant['authorized_date'])) . "\n";
        }

        if (isset($grant['last_activity'])) {
            echo "   Última actividad: " . date('Y-m-d H:i:s', strtotime($grant['last_activity'])) . "\n";
        }

        if (isset($grant['scopes'])) {
            echo "   Scopes: " . implode(', ', $grant['scopes']) . "\n";
        }

        echo "\n";
    }

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

### Estadísticas de Usuarios

```php
<?php

try {
    $appGrants = $meli->getApplicationGrants($accessToken, $clientId);

    // Calcular estadísticas
    $totalUsers = count($appGrants);
    $activeUsers = count(array_filter($appGrants, fn($grant) => $grant['status'] === 'active'));
    $inactiveUsers = count(array_filter($appGrants, fn($grant) => $grant['status'] === 'inactive'));

    // Usuarios con diferentes scopes
    $usersWithOfflineAccess = count(array_filter($appGrants, function($grant) {
        return isset($grant['scopes']) && in_array('offline_access', $grant['scopes']);
    }));

    echo "📊 Estadísticas de Usuarios:\n";
    echo "============================\n";
    echo "Total de usuarios: {$totalUsers}\n";
    echo "Usuarios activos: {$activeUsers}\n";
    echo "Usuarios inactivos: {$inactiveUsers}\n";
    echo "Con offline_access: {$usersWithOfflineAccess}\n";
    echo "Porcentaje activos: " . round(($activeUsers / $totalUsers) * 100, 2) . "%\n\n";

    // Usuarios más recientes
    if (!empty($appGrants)) {
        usort($appGrants, function($a, $b) {
            $dateA = strtotime($a['authorized_date'] ?? '1970-01-01');
            $dateB = strtotime($b['authorized_date'] ?? '1970-01-01');
            return $dateB - $dateA;
        });

        echo "🆕 Usuarios Más Recientes:\n";
        foreach (array_slice($appGrants, 0, 5) as $grant) {
            echo "   - " . $grant['nickname'] . " (" . date('Y-m-d', strtotime($grant['authorized_date'])) . ")\n";
        }
    }

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
```

## 4. Revocar Autorización de Usuario

### Revocar Permisos de un Usuario

```php
<?php

try {
    $userId = $_SESSION['user_id'];

    // Revocar autorización del usuario actual
    $result = $meli->revokeUserAuthorization($accessToken, $userId, $clientId);

    echo "✅ Autorización revocada exitosamente\n";
    echo "Usuario ID: " . $userId . "\n";
    echo "Aplicación ID: " . $clientId . "\n";

    // Limpiar sesión después de revocar
    session_destroy();
    session_start();

    echo "✅ Sesión limpiada\n";
    echo "💡 El usuario debe autorizar nuevamente para usar la aplicación\n";

} catch (GenericException $e) {
    echo "❌ Error al revocar autorización: " . $e->getMessage() . "\n";
}
```

### Revocar Autorización de Otro Usuario (Admin)

```php
<?php

try {
    $targetUserId = '123456789'; // ID del usuario a revocar

    // Revocar autorización de otro usuario
    $result = $meli->revokeUserAuthorization($accessToken, $targetUserId, $clientId);

    echo "✅ Autorización revocada para usuario: " . $targetUserId . "\n";
    echo "Aplicación: " . $clientId . "\n";
    echo "Resultado: " . json_encode($result) . "\n";

} catch (GenericException $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";

    if ($e->getCode() === 403) {
        echo "💡 No tienes permisos para revocar autorizaciones de otros usuarios\n";
    }
}
```

## 5. Clase ApplicationManager

Crear una clase para gestionar aplicaciones de forma organizada:

```php
<?php
// ApplicationManager.php

use Tepuilabs\MeliServices\MeliServices;
use Tepuilabs\MeliServices\Exceptions\GenericException;

class ApplicationManager {
    private MeliServices $meli;
    private string $accessToken;
    private string $clientId;

    public function __construct(MeliServices $meli, string $accessToken, string $clientId) {
        $this->meli = $meli;
        $this->accessToken = $accessToken;
        $this->clientId = $clientId;
    }

    public function getApplicationDetails(): array {
        return $this->meli->getApplicationDetails($this->accessToken, $this->clientId);
    }

    public function getUserApplications(int $userId): array {
        return $this->meli->getUserApplications($this->accessToken, $userId);
    }

    public function getApplicationGrants(): array {
        return $this->meli->getApplicationGrants($this->accessToken, $this->clientId);
    }

    public function revokeUserAuthorization(int $userId): array {
        return $this->meli->revokeUserAuthorization($this->accessToken, $userId, $this->clientId);
    }

    public function getApplicationStats(): array {
        $details = $this->getApplicationDetails();
        $grants = $this->getApplicationGrants();

        return [
            'app_info' => [
                'id' => $details['id'],
                'name' => $details['name'],
                'status' => $details['status'],
                'created' => $details['created'] ?? null
            ],
            'users' => [
                'total' => count($grants),
                'active' => count(array_filter($grants, fn($g) => $g['status'] === 'active')),
                'inactive' => count(array_filter($grants, fn($g) => $g['status'] === 'inactive'))
            ],
            'scopes' => [
                'with_offline_access' => count(array_filter($grants, function($grant) {
                    return isset($grant['scopes']) && in_array('offline_access', $grant['scopes']);
                }))
            ]
        ];
    }

    public function getRecentUsers(int $limit = 10): array {
        $grants = $this->getApplicationGrants();

        // Ordenar por fecha de autorización
        usort($grants, function($a, $b) {
            $dateA = strtotime($a['authorized_date'] ?? '1970-01-01');
            $dateB = strtotime($b['authorized_date'] ?? '1970-01-01');
            return $dateB - $dateA;
        });

        return array_slice($grants, 0, $limit);
    }

    public function getInactiveUsers(): array {
        $grants = $this->getApplicationGrants();

        return array_filter($grants, function($grant) {
            return $grant['status'] === 'inactive';
        });
    }

    public function revokeInactiveUsers(): array {
        $inactiveUsers = $this->getInactiveUsers();
        $revoked = [];

        foreach ($inactiveUsers as $user) {
            try {
                $result = $this->revokeUserAuthorization($user['user_id']);
                $revoked[] = [
                    'user_id' => $user['user_id'],
                    'nickname' => $user['nickname'],
                    'success' => true
                ];
            } catch (GenericException $e) {
                $revoked[] = [
                    'user_id' => $user['user_id'],
                    'nickname' => $user['nickname'],
                    'success' => false,
                    'error' => $e->getMessage()
                ];
            }
        }

        return $revoked;
    }
}

// Uso
$appManager = new ApplicationManager($meli, $accessToken, $clientId);

try {
    // Obtener estadísticas
    $stats = $appManager->getApplicationStats();
    echo "📊 Estadísticas de la aplicación:\n";
    echo "Nombre: " . $stats['app_info']['name'] . "\n";
    echo "Usuarios totales: " . $stats['users']['total'] . "\n";
    echo "Usuarios activos: " . $stats['users']['active'] . "\n";

    // Obtener usuarios recientes
    $recentUsers = $appManager->getRecentUsers(5);
    echo "\n🆕 Usuarios recientes:\n";
    foreach ($recentUsers as $user) {
        echo "- " . $user['nickname'] . " (" . date('Y-m-d', strtotime($user['authorized_date'])) . ")\n";
    }

} catch (GenericException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```

## 6. Dashboard de Gestión de Aplicaciones

Crear un dashboard completo para gestionar la aplicación:

```php
<?php
// app_dashboard.php

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
$clientId = 'tu_client_id';

$config = MeliConfig::forAuthorization(
    clientId: $clientId,
    clientSecret: 'tu_client_secret',
    redirectUri: 'http://localhost:9000/callback'
);

$meli = new MeliServices($config);
$appManager = new ApplicationManager($meli, $accessToken, $clientId);

$action = $_GET['action'] ?? '';
$error = null;
$success = null;

try {
    switch ($action) {
        case 'revoke_user':
            $userId = $_GET['user_id'] ?? '';
            if ($userId) {
                $appManager->revokeUserAuthorization($userId);
                $success = "Autorización revocada para usuario: {$userId}";
            }
            break;

        case 'revoke_inactive':
            $revoked = $appManager->revokeInactiveUsers();
            $success = "Revocadas " . count($revoked) . " autorizaciones inactivas";
            break;
    }

    $appDetails = $appManager->getApplicationDetails();
    $stats = $appManager->getApplicationStats();
    $recentUsers = $appManager->getRecentUsers(10);
    $inactiveUsers = $appManager->getInactiveUsers();

} catch (GenericException $e) {
    $error = $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard de Aplicación - Mercado Libre</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .dashboard { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .card { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; }
        .stat-item { text-align: center; padding: 15px; background: white; border-radius: 5px; }
        .user-list { max-height: 300px; overflow-y: auto; }
        .user-item { padding: 10px; border-bottom: 1px solid #ddd; }
        .btn { background: #007bff; color: white; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; margin: 2px; }
        .btn-danger { background: #dc3545; }
        .btn-warning { background: #ffc107; color: black; }
        .success { background: #d4edda; color: #155724; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .error { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>📱 Dashboard de Gestión de Aplicación</h1>

    <?php if ($error): ?>
        <div class="error">❌ <?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <?php if ($success): ?>
        <div class="success">✅ <?= htmlspecialchars($success) ?></div>
    <?php endif; ?>

    <div class="dashboard">
        <div>
            <div class="card">
                <h2>📊 Información de la Aplicación</h2>
                <p><strong>Nombre:</strong> <?= htmlspecialchars($appDetails['name']) ?></p>
                <p><strong>ID:</strong> <?= htmlspecialchars($appDetails['id']) ?></p>
                <p><strong>Estado:</strong> <?= htmlspecialchars($appDetails['status']) ?></p>
                <p><strong>URL:</strong> <a href="<?= htmlspecialchars($appDetails['url']) ?>" target="_blank"><?= htmlspecialchars($appDetails['url']) ?></a></p>
            </div>

            <div class="card">
                <h2>📈 Estadísticas</h2>
                <div class="stats">
                    <div class="stat-item">
                        <h3><?= $stats['users']['total'] ?></h3>
                        <p>Total Usuarios</p>
                    </div>
                    <div class="stat-item">
                        <h3><?= $stats['users']['active'] ?></h3>
                        <p>Usuarios Activos</p>
                    </div>
                    <div class="stat-item">
                        <h3><?= $stats['users']['inactive'] ?></h3>
                        <p>Usuarios Inactivos</p>
                    </div>
                </div>
            </div>
        </div>

        <div>
            <div class="card">
                <h2>🆕 Usuarios Recientes</h2>
                <div class="user-list">
                    <?php foreach ($recentUsers as $user): ?>
                        <div class="user-item">
                            <strong><?= htmlspecialchars($user['nickname']) ?></strong>
                            <br>
                            <small>ID: <?= $user['user_id'] ?> | <?= date('Y-m-d H:i', strtotime($user['authorized_date'])) ?></small>
                            <br>
                            <a href="?action=revoke_user&user_id=<?= $user['user_id'] ?>" class="btn btn-danger" onclick="return confirm('¿Revocar autorización?')">Revocar</a>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>

            <div class="card">
                <h2>⚠️ Usuarios Inactivos</h2>
                <p>Total: <?= count($inactiveUsers) ?></p>
                <?php if (!empty($inactiveUsers)): ?>
                    <a href="?action=revoke_inactive" class="btn btn-warning" onclick="return confirm('¿Revocar todas las autorizaciones inactivas?')">Revocar Todos</a>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div style="margin-top: 20px;">
        <a href="dashboard.php" class="btn">← Volver al Dashboard</a>
        <a href="?logout=1" class="btn btn-danger">🚪 Cerrar Sesión</a>
    </div>
</body>
</html>
```

## 7. Manejo de Errores Específicos

```php
<?php

try {
    $appDetails = $meli->getApplicationDetails($accessToken, $clientId);
} catch (GenericException $e) {
    $errorCode = $e->getCode();
    $errorMessage = $e->getMessage();

    switch ($errorCode) {
        case 400:
            if (strpos($errorMessage, 'invalid_app_id') !== false) {
                echo "❌ ID de aplicación inválido\n";
                echo "💡 Verifica que el client_id sea correcto\n";
            }
            break;

        case 401:
            echo "❌ No autorizado para acceder a esta aplicación\n";
            echo "💡 Verifica que el token tenga permisos de administración\n";
            break;

        case 403:
            echo "❌ Acceso denegado\n";
            echo "💡 No tienes permisos para gestionar esta aplicación\n";
            break;

        case 404:
            echo "❌ Aplicación no encontrada\n";
            echo "💡 Verifica que la aplicación exista y esté activa\n";
            break;

        default:
            echo "❌ Error desconocido: {$errorMessage}\n";
    }
}
```

## Resumen

En este capítulo has aprendido:

- ✅ Cómo obtener detalles completos de tu aplicación
- ✅ Listar usuarios que autorizaron tu app
- ✅ Ver usuarios conectados a tu aplicación
- ✅ Revocar autorizaciones de usuarios
- ✅ Clase ApplicationManager para gestión organizada
- ✅ Dashboard completo de gestión
- ✅ Manejo de errores específicos
- ✅ Estadísticas y análisis de usuarios

## Próximos Pasos

- [07. Manejo de Errores Avanzado](./07-manejo-errores-avanzado.md)
- [08. Seguridad y Mejores Prácticas](./08-seguridad-mejores-practicas.md)
- [09. Casos de Uso Avanzados](./09-casos-uso-avanzados.md)
