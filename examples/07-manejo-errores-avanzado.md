# 07. Manejo de Errores Avanzado

## Introducción

El manejo robusto de errores es crucial para aplicaciones en producción. En este capítulo aprenderás estrategias avanzadas para manejar errores específicos de la API de Mercado Libre, implementar reintentos automáticos, logging detallado y fallbacks inteligentes.

## Tipos de Errores

### Errores HTTP Comunes

| Código | Descripción | Causa Común |
|--------|-------------|-------------|
| 400 | Bad Request | Parámetros inválidos |
| 401 | Unauthorized | Token expirado o inválido |
| 403 | Forbidden | Permisos insuficientes |
| 404 | Not Found | Recurso no encontrado |
| 429 | Too Many Requests | Rate limit excedido |
| 500 | Internal Server Error | Error del servidor ML |
| 502/503/504 | Gateway/Service Unavailable | Servicio no disponible |

## 1. Clase ErrorHandler Avanzada

```php
<?php
// AdvancedErrorHandler.php

use Tepuilabs\MeliServices\Exceptions\GenericException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ConnectException;

class AdvancedErrorHandler {
    private array $retryableErrors = [429, 500, 502, 503, 504];
    private array $tokenErrors = [401, 403];
    private array $permanentErrors = [400, 404];
    private int $maxRetries = 3;
    private int $retryDelay = 1000; // ms

    public function handleError(GenericException $e, callable $retryCallback = null): array {
        $errorCode = $e->getCode();
        $errorMessage = $e->getMessage();

        // Log del error
        $this->logError($e);

        // Determinar tipo de error
        if (in_array($errorCode, $this->retryableErrors)) {
            return $this->handleRetryableError($e, $retryCallback);
        } elseif (in_array($errorCode, $this->tokenErrors)) {
            return $this->handleTokenError($e);
        } elseif (in_array($errorCode, $this->permanentErrors)) {
            return $this->handlePermanentError($e);
        } else {
            return $this->handleUnknownError($e);
        }
    }

    private function handleRetryableError(GenericException $e, callable $retryCallback = null): array {
        $attempts = 0;
        $lastError = $e;

        while ($attempts < $this->maxRetries) {
            $attempts++;

            try {
                // Esperar antes del reintento
                if ($attempts > 1) {
                    $delay = $this->retryDelay * $attempts; // Backoff exponencial
                    usleep($delay * 1000);
                }

                if ($retryCallback) {
                    $result = $retryCallback();
                    return [
                        'success' => true,
                        'data' => $result,
                        'attempts' => $attempts,
                        'retried' => $attempts > 1
                    ];
                }

            } catch (GenericException $retryError) {
                $lastError = $retryError;
                $this->logError($retryError, "Retry attempt {$attempts}");

                // Si no es un error reintentable, salir
                if (!in_array($retryError->getCode(), $this->retryableErrors)) {
                    break;
                }
            }
        }

        return [
            'success' => false,
            'error' => $lastError->getMessage(),
            'code' => $lastError->getCode(),
            'attempts' => $attempts,
            'type' => 'retry_exhausted'
        ];
    }

    private function handleTokenError(GenericException $e): array {
        $errorCode = $e->getCode();

        if ($errorCode === 401) {
            return [
                'success' => false,
                'error' => 'Token expirado o inválido',
                'code' => $errorCode,
                'action' => 'refresh_token',
                'type' => 'token_error'
            ];
        } elseif ($errorCode === 403) {
            return [
                'success' => false,
                'error' => 'Permisos insuficientes',
                'code' => $errorCode,
                'action' => 'reauthorize',
                'type' => 'permission_error'
            ];
        }

        return [
            'success' => false,
            'error' => $e->getMessage(),
            'code' => $errorCode,
            'type' => 'token_error'
        ];
    }

    private function handlePermanentError(GenericException $e): array {
        $errorCode = $e->getCode();

        if ($errorCode === 400) {
            return [
                'success' => false,
                'error' => 'Parámetros inválidos en la solicitud',
                'code' => $errorCode,
                'action' => 'fix_parameters',
                'type' => 'validation_error'
            ];
        } elseif ($errorCode === 404) {
            return [
                'success' => false,
                'error' => 'Recurso no encontrado',
                'code' => $errorCode,
                'action' => 'check_resource',
                'type' => 'not_found'
            ];
        }

        return [
            'success' => false,
            'error' => $e->getMessage(),
            'code' => $errorCode,
            'type' => 'permanent_error'
        ];
    }

    private function handleUnknownError(GenericException $e): array {
        return [
            'success' => false,
            'error' => $e->getMessage(),
            'code' => $e->getCode(),
            'type' => 'unknown_error'
        ];
    }

    private function logError(GenericException $e, string $context = ''): void {
        $logData = [
            'timestamp' => date('Y-m-d H:i:s'),
            'error_code' => $e->getCode(),
            'error_message' => $e->getMessage(),
            'context' => $context,
            'trace' => $e->getTraceAsString()
        ];

        error_log(json_encode($logData) . "\n", 3, 'logs/meli_errors.log');
    }

    public function setMaxRetries(int $maxRetries): void {
        $this->maxRetries = $maxRetries;
    }

    public function setRetryDelay(int $delay): void {
        $this->retryDelay = $delay;
    }
}
```

## 2. Estrategias de Retry Inteligente

### Retry con Backoff Exponencial

```php
<?php

use Tepuilabs\MeliServices\MeliServices;
use Tepuilabs\MeliServices\Exceptions\GenericException;

class RetryStrategy {
    private int $maxRetries;
    private int $baseDelay;
    private float $backoffMultiplier;

    public function __construct(int $maxRetries = 3, int $baseDelay = 1000, float $backoffMultiplier = 2.0) {
        $this->maxRetries = $maxRetries;
        $this->baseDelay = $baseDelay;
        $this->backoffMultiplier = $backoffMultiplier;
    }

    public function executeWithRetry(callable $operation): array {
        $attempts = 0;
        $lastError = null;

        while ($attempts < $this->maxRetries) {
            $attempts++;

            try {
                $result = $operation();
                return [
                    'success' => true,
                    'data' => $result,
                    'attempts' => $attempts
                ];

            } catch (GenericException $e) {
                $lastError = $e;

                // Verificar si es un error reintentable
                if (!$this->isRetryableError($e)) {
                    break;
                }

                // Calcular delay con backoff exponencial
                if ($attempts < $this->maxRetries) {
                    $delay = $this->baseDelay * pow($this->backoffMultiplier, $attempts - 1);
                    $delay += rand(0, 1000); // Jitter aleatorio

                    usleep($delay * 1000);
                }
            }
        }

        return [
            'success' => false,
            'error' => $lastError->getMessage(),
            'code' => $lastError->getCode(),
            'attempts' => $attempts
        ];
    }

    private function isRetryableError(GenericException $e): bool {
        $retryableCodes = [429, 500, 502, 503, 504];
        return in_array($e->getCode(), $retryableCodes);
    }
}

// Uso
$retryStrategy = new RetryStrategy(3, 1000, 2.0);

$result = $retryStrategy->executeWithRetry(function() use ($meli, $accessToken) {
    return $meli->get('/users/me', $accessToken);
});

if ($result['success']) {
    echo "✅ Operación exitosa después de {$result['attempts']} intentos\n";
    print_r($result['data']);
} else {
    echo "❌ Error después de {$result['attempts']} intentos: {$result['error']}\n";
}
```

### Retry con Circuit Breaker

```php
<?php

class CircuitBreaker {
    private string $name;
    private int $failureThreshold;
    private int $timeout;
    private int $failureCount = 0;
    private int $lastFailureTime = 0;
    private string $state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN

    public function __construct(string $name, int $failureThreshold = 5, int $timeout = 60) {
        $this->name = $name;
        $this->failureThreshold = $failureThreshold;
        $this->timeout = $timeout;
    }

    public function execute(callable $operation): array {
        if ($this->state === 'OPEN') {
            if ($this->shouldAttemptReset()) {
                $this->state = 'HALF_OPEN';
            } else {
                return [
                    'success' => false,
                    'error' => 'Circuit breaker is OPEN',
                    'type' => 'circuit_breaker_open'
                ];
            }
        }

        try {
            $result = $operation();
            $this->onSuccess();

            return [
                'success' => true,
                'data' => $result
            ];

        } catch (Exception $e) {
            $this->onFailure();

            return [
                'success' => false,
                'error' => $e->getMessage(),
                'type' => 'operation_failed'
            ];
        }
    }

    private function onSuccess(): void {
        $this->failureCount = 0;
        $this->state = 'CLOSED';
    }

    private function onFailure(): void {
        $this->failureCount++;
        $this->lastFailureTime = time();

        if ($this->failureCount >= $this->failureThreshold) {
            $this->state = 'OPEN';
        }
    }

    private function shouldAttemptReset(): bool {
        return (time() - $this->lastFailureTime) >= $this->timeout;
    }

    public function getState(): string {
        return $this->state;
    }

    public function getFailureCount(): int {
        return $this->failureCount;
    }
}

// Uso
$circuitBreaker = new CircuitBreaker('meli_api', 5, 60);

$result = $circuitBreaker->execute(function() use ($meli, $accessToken) {
    return $meli->get('/users/me', $accessToken);
});

if ($result['success']) {
    echo "✅ Operación exitosa\n";
} else {
    echo "❌ Error: {$result['error']}\n";
    echo "Estado del circuit breaker: " . $circuitBreaker->getState() . "\n";
}
```

## 3. Logging Avanzado

### Logger Especializado para Mercado Libre

```php
<?php

class MeliLogger {
    private string $logFile;
    private string $errorLogFile;
    private bool $debugMode;

    public function __construct(string $logFile = 'logs/meli.log', string $errorLogFile = 'logs/meli_errors.log', bool $debugMode = false) {
        $this->logFile = $logFile;
        $this->errorLogFile = $errorLogFile;
        $this->debugMode = $debugMode;

        // Crear directorio de logs si no existe
        $logDir = dirname($logFile);
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
    }

    public function logRequest(string $method, string $endpoint, array $params = [], ?string $accessToken = null): void {
        $logData = [
            'timestamp' => date('Y-m-d H:i:s'),
            'type' => 'request',
            'method' => $method,
            'endpoint' => $endpoint,
            'params' => $this->sanitizeParams($params),
            'token_preview' => $accessToken ? substr($accessToken, 0, 10) . '...' : null
        ];

        $this->writeLog($logData, $this->logFile);
    }

    public function logResponse(string $method, string $endpoint, array $response, int $statusCode, float $duration): void {
        $logData = [
            'timestamp' => date('Y-m-d H:i:s'),
            'type' => 'response',
            'method' => $method,
            'endpoint' => $endpoint,
            'status_code' => $statusCode,
            'duration_ms' => round($duration * 1000, 2),
            'response_size' => strlen(json_encode($response)),
            'response_preview' => $this->debugMode ? array_slice($response, 0, 3) : null
        ];

        $this->writeLog($logData, $this->logFile);
    }

    public function logError(GenericException $e, string $context = ''): void {
        $logData = [
            'timestamp' => date('Y-m-d H:i:s'),
            'type' => 'error',
            'error_code' => $e->getCode(),
            'error_message' => $e->getMessage(),
            'context' => $context,
            'trace' => $this->debugMode ? $e->getTraceAsString() : null
        ];

        $this->writeLog($logData, $this->errorLogFile);
    }

    public function logTokenRefresh(string $oldToken, string $newToken, bool $success): void {
        $logData = [
            'timestamp' => date('Y-m-d H:i:s'),
            'type' => 'token_refresh',
            'success' => $success,
            'old_token_preview' => substr($oldToken, 0, 10) . '...',
            'new_token_preview' => $success ? substr($newToken, 0, 10) . '...' : null
        ];

        $this->writeLog($logData, $this->logFile);
    }

    private function sanitizeParams(array $params): array {
        $sensitiveKeys = ['client_secret', 'access_token', 'refresh_token', 'code'];

        foreach ($sensitiveKeys as $key) {
            if (isset($params[$key])) {
                $params[$key] = substr($params[$key], 0, 10) . '...';
            }
        }

        return $params;
    }

    private function writeLog(array $data, string $file): void {
        $logLine = json_encode($data) . "\n";
        file_put_contents($file, $logLine, FILE_APPEND | LOCK_EX);
    }

    public function getStats(): array {
        $stats = [
            'total_requests' => 0,
            'total_errors' => 0,
            'avg_response_time' => 0,
            'error_rate' => 0
        ];

        if (file_exists($this->logFile)) {
            $lines = file($this->logFile);
            $requests = 0;
            $errors = 0;
            $totalTime = 0;

            foreach ($lines as $line) {
                $data = json_decode($line, true);
                if ($data) {
                    if ($data['type'] === 'request') {
                        $requests++;
                    } elseif ($data['type'] === 'response' && isset($data['duration_ms'])) {
                        $totalTime += $data['duration_ms'];
                    }
                }
            }

            if (file_exists($this->errorLogFile)) {
                $errorLines = file($this->errorLogFile);
                $errors = count($errorLines);
            }

            $stats['total_requests'] = $requests;
            $stats['total_errors'] = $errors;
            $stats['avg_response_time'] = $requests > 0 ? $totalTime / $requests : 0;
            $stats['error_rate'] = $requests > 0 ? ($errors / $requests) * 100 : 0;
        }

        return $stats;
    }
}

// Uso
$logger = new MeliLogger('logs/meli.log', 'logs/meli_errors.log', true);

// Log de request
$logger->logRequest('GET', '/users/me', [], $accessToken);

// Log de response
$logger->logResponse('GET', '/users/me', $response, 200, 0.5);

// Log de error
try {
    $meli->get('/invalid/endpoint', $accessToken);
} catch (GenericException $e) {
    $logger->logError($e, 'API call failed');
}

// Obtener estadísticas
$stats = $logger->getStats();
echo "📊 Estadísticas de API:\n";
echo "Total requests: " . $stats['total_requests'] . "\n";
echo "Total errors: " . $stats['total_errors'] . "\n";
echo "Error rate: " . round($stats['error_rate'], 2) . "%\n";
echo "Avg response time: " . round($stats['avg_response_time'], 2) . "ms\n";
```

## 4. Fallbacks y Degradación Graceful

### Sistema de Fallbacks

```php
<?php

class FallbackManager {
    private array $fallbacks = [];
    private MeliLogger $logger;

    public function __construct(MeliLogger $logger) {
        $this->logger = $logger;
    }

    public function addFallback(string $operation, callable $fallback): void {
        $this->fallbacks[$operation] = $fallback;
    }

    public function executeWithFallback(string $operation, callable $mainOperation): array {
        try {
            $result = $mainOperation();
            return [
                'success' => true,
                'data' => $result,
                'source' => 'primary'
            ];

        } catch (GenericException $e) {
            $this->logger->logError($e, "Primary operation failed: {$operation}");

            // Intentar fallback
            if (isset($this->fallbacks[$operation])) {
                try {
                    $fallbackResult = $this->fallbacks[$operation]();
                    return [
                        'success' => true,
                        'data' => $fallbackResult,
                        'source' => 'fallback'
                    ];

                } catch (Exception $fallbackError) {
                    $this->logger->logError($fallbackError, "Fallback also failed: {$operation}");

                    return [
                        'success' => false,
                        'error' => 'Both primary and fallback operations failed',
                        'primary_error' => $e->getMessage(),
                        'fallback_error' => $fallbackError->getMessage()
                    ];
                }
            }

            return [
                'success' => false,
                'error' => $e->getMessage(),
                'code' => $e->getCode()
            ];
        }
    }
}

// Uso
$fallbackManager = new FallbackManager($logger);

// Agregar fallbacks
$fallbackManager->addFallback('get_user_profile', function() {
    // Fallback: datos básicos del usuario desde caché
    return [
        'id' => $_SESSION['user_id'] ?? 'unknown',
        'nickname' => $_SESSION['user_nickname'] ?? 'Usuario',
        'email' => $_SESSION['user_email'] ?? 'email@example.com'
    ];
});

$fallbackManager->addFallback('get_user_items', function() {
    // Fallback: lista vacía
    return ['results' => [], 'paging' => ['total' => 0]];
});

// Ejecutar con fallback
$result = $fallbackManager->executeWithFallback('get_user_profile', function() use ($meli, $accessToken) {
    return $meli->get('/users/me', $accessToken);
});

if ($result['success']) {
    echo "✅ Datos obtenidos desde: " . $result['source'] . "\n";
    print_r($result['data']);
} else {
    echo "❌ Error: {$result['error']}\n";
}
```

## 5. Monitoreo y Alertas

### Sistema de Monitoreo

```php
<?php

class MeliMonitor {
    private MeliLogger $logger;
    private array $thresholds;
    private array $alerts = [];

    public function __construct(MeliLogger $logger, array $thresholds = []) {
        $this->logger = $logger;
        $this->thresholds = array_merge([
            'error_rate_threshold' => 5.0, // 5%
            'response_time_threshold' => 2000, // 2 segundos
            'consecutive_failures_threshold' => 3
        ], $thresholds);
    }

    public function checkHealth(): array {
        $stats = $this->logger->getStats();
        $issues = [];

        // Verificar tasa de errores
        if ($stats['error_rate'] > $this->thresholds['error_rate_threshold']) {
            $issues[] = [
                'type' => 'high_error_rate',
                'message' => "Error rate is {$stats['error_rate']}% (threshold: {$this->thresholds['error_rate_threshold']}%)",
                'severity' => 'high'
            ];
        }

        // Verificar tiempo de respuesta
        if ($stats['avg_response_time'] > $this->thresholds['response_time_threshold']) {
            $issues[] = [
                'type' => 'slow_response',
                'message' => "Average response time is {$stats['avg_response_time']}ms (threshold: {$this->thresholds['response_time_threshold']}ms)",
                'severity' => 'medium'
            ];
        }

        return [
            'healthy' => empty($issues),
            'issues' => $issues,
            'stats' => $stats
        ];
    }

    public function sendAlert(string $message, string $severity = 'medium'): void {
        $alert = [
            'timestamp' => date('Y-m-d H:i:s'),
            'message' => $message,
            'severity' => $severity
        ];

        $this->alerts[] = $alert;

        // Enviar alerta por email, Slack, etc.
        $this->sendNotification($alert);
    }

    private function sendNotification(array $alert): void {
        // Implementar envío de notificaciones
        // Email, Slack, Discord, etc.

        $subject = "[Meli API Alert] {$alert['severity']}: {$alert['message']}";
        $body = json_encode($alert, JSON_PRETTY_PRINT);

        // Ejemplo: enviar email
        // mail('admin@example.com', $subject, $body);

        // Ejemplo: enviar a Slack
        // $this->sendSlackNotification($alert);
    }

    public function getAlerts(): array {
        return $this->alerts;
    }
}

// Uso
$monitor = new MeliMonitor($logger, [
    'error_rate_threshold' => 3.0,
    'response_time_threshold' => 1500
]);

// Verificar salud del sistema
$health = $monitor->checkHealth();

if (!$health['healthy']) {
    echo "⚠️ Problemas detectados:\n";
    foreach ($health['issues'] as $issue) {
        echo "- {$issue['message']} (Severity: {$issue['severity']})\n";
        $monitor->sendAlert($issue['message'], $issue['severity']);
    }
} else {
    echo "✅ Sistema saludable\n";
}

echo "📊 Estadísticas:\n";
print_r($health['stats']);
```

## 6. Ejemplo Completo de Integración

```php
<?php
// advanced_error_handling.php

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;
use Tepuilabs\MeliServices\Exceptions\GenericException;

require 'vendor/autoload.php';

session_start();

// Configuración
$accessToken = $_SESSION['access_token'] ?? null;
$clientId = 'tu_client_id';

if (!$accessToken) {
    die("❌ No hay access token disponible");
}

$config = MeliConfig::forAuthorization(
    clientId: $clientId,
    clientSecret: 'tu_client_secret',
    redirectUri: 'http://localhost:9000/callback'
);

$meli = new MeliServices($config);

// Inicializar componentes
$logger = new MeliLogger('logs/meli.log', 'logs/meli_errors.log', true);
$errorHandler = new AdvancedErrorHandler();
$retryStrategy = new RetryStrategy(3, 1000, 2.0);
$circuitBreaker = new CircuitBreaker('meli_api', 5, 60);
$fallbackManager = new FallbackManager($logger);
$monitor = new MeliMonitor($logger);

// Configurar fallbacks
$fallbackManager->addFallback('get_user_profile', function() {
    return [
        'id' => $_SESSION['user_id'] ?? 'unknown',
        'nickname' => 'Usuario (Fallback)',
        'email' => 'fallback@example.com'
    ];
});

// Función principal con manejo de errores avanzado
function makeApiCall(MeliServices $meli, string $accessToken, string $endpoint, array $components): array {
    $logger = $components['logger'];
    $retryStrategy = $components['retryStrategy'];
    $circuitBreaker = $components['circuitBreaker'];
    $fallbackManager = $components['fallbackManager'];

    // Log de request
    $logger->logRequest('GET', $endpoint, [], $accessToken);

    // Ejecutar con circuit breaker y retry
    $result = $circuitBreaker->execute(function() use ($retryStrategy, $meli, $accessToken, $endpoint) {
        return $retryStrategy->executeWithRetry(function() use ($meli, $accessToken, $endpoint) {
            return $meli->get($endpoint, $accessToken);
        });
    });

    if ($result['success']) {
        // Log de response exitosa
        $logger->logResponse('GET', $endpoint, $result['data'], 200, 0.5);
        return $result;
    }

    // Si falló, intentar fallback
    return $fallbackManager->executeWithFallback($endpoint, function() use ($meli, $accessToken, $endpoint) {
        return $meli->get($endpoint, $accessToken);
    });
}

// Componentes
$components = [
    'logger' => $logger,
    'retryStrategy' => $retryStrategy,
    'circuitBreaker' => $circuitBreaker,
    'fallbackManager' => $fallbackManager,
    'monitor' => $monitor
];

// Hacer llamada a la API
$result = makeApiCall($meli, $accessToken, '/users/me', $components);

if ($result['success']) {
    echo "✅ Operación exitosa\n";
    echo "Fuente: " . ($result['source'] ?? 'primary') . "\n";
    print_r($result['data']);
} else {
    echo "❌ Error: {$result['error']}\n";
}

// Verificar salud del sistema
$health = $monitor->checkHealth();
echo "\n📊 Estado del sistema:\n";
echo "Saludable: " . ($health['healthy'] ? 'Sí' : 'No') . "\n";
echo "Tasa de errores: " . round($health['stats']['error_rate'], 2) . "%\n";
echo "Tiempo promedio: " . round($health['stats']['avg_response_time'], 2) . "ms\n";
```

## Resumen

En este capítulo has aprendido:

- ✅ Clase AdvancedErrorHandler para manejo robusto de errores
- ✅ Estrategias de retry con backoff exponencial
- ✅ Circuit breaker para prevenir fallos en cascada
- ✅ Sistema de logging avanzado y especializado
- ✅ Fallbacks y degradación graceful
- ✅ Monitoreo y alertas automáticas
- ✅ Integración completa de todos los componentes
- ✅ Manejo específico de errores de Mercado Libre

## Próximos Pasos

- [08. Seguridad y Mejores Prácticas](./08-seguridad-mejores-practicas.md)
- [09. Casos de Uso Avanzados](./09-casos-uso-avanzados.md)
