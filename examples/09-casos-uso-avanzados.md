# 09. Casos de Uso Avanzados

## Introducción

En este capítulo final exploraremos casos de uso avanzados y técnicas especializadas para usar la librería `mini-meli` en escenarios complejos. Aprenderás sobre webhooks, procesamiento en lote, caché, integración con frameworks y optimización de rendimiento.

## Casos de Uso Avanzados

### 🔄 Webhooks
### 📦 Procesamiento en Lote
### ⚡ Caché y Optimización
### 🏗️ Integración con Frameworks
### 📊 Monitoreo Avanzado

## 1. Webhooks

### Webhook Handler

```php
<?php
// WebhookHandler.php

use Tepuilabs\MeliServices\Exceptions\GenericException;

class WebhookHandler {
    private string $secretKey;
    private MeliLogger $logger;
    private array $supportedTopics = [
        'items',
        'questions',
        'orders',
        'payments',
        'messages'
    ];

    public function __construct(string $secretKey, MeliLogger $logger) {
        $this->secretKey = $secretKey;
        $this->logger = $logger;
    }

    public function handleWebhook(): array {
        try {
            // Obtener datos del webhook
            $payload = file_get_contents('php://input');
            $headers = getallheaders();

            // Log del webhook
            $this->logger->logSecurityEvent('webhook_received', [
                'payload_size' => strlen($payload),
                'headers' => $headers
            ]);

            // Verificar firma del webhook
            if (!$this->verifySignature($payload, $headers)) {
                throw new Exception('Firma del webhook inválida');
            }

            // Parsear payload
            $data = json_decode($payload, true);
            if (!$data) {
                throw new Exception('Payload JSON inválido');
            }

            // Procesar webhook
            $result = $this->processWebhook($data);

            $this->logger->logSecurityEvent('webhook_processed', [
                'topic' => $data['topic'] ?? 'unknown',
                'resource_id' => $data['resource_id'] ?? 'unknown'
            ]);

            return [
                'success' => true,
                'result' => $result
            ];

        } catch (Exception $e) {
            $this->logger->logSecurityEvent('webhook_error', [
                'error' => $e->getMessage()
            ], 'error');

            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    private function verifySignature(string $payload, array $headers): bool {
        $signature = $headers['X-Hub-Signature'] ?? '';

        if (empty($signature)) {
            return false;
        }

        $expectedSignature = 'sha256=' . hash_hmac('sha256', $payload, $this->secretKey);

        return hash_equals($expectedSignature, $signature);
    }

    private function processWebhook(array $data): array {
        $topic = $data['topic'] ?? '';
        $resourceId = $data['resource_id'] ?? '';
        $userId = $data['user_id'] ?? '';

        switch ($topic) {
            case 'items':
                return $this->handleItemWebhook($resourceId, $userId);

            case 'questions':
                return $this->handleQuestionWebhook($resourceId, $userId);

            case 'orders':
                return $this->handleOrderWebhook($resourceId, $userId);

            case 'payments':
                return $this->handlePaymentWebhook($resourceId, $userId);

            case 'messages':
                return $this->handleMessageWebhook($resourceId, $userId);

            default:
                throw new Exception("Topic no soportado: {$topic}");
        }
    }

    private function handleItemWebhook(string $itemId, string $userId): array {
        // Procesar cambios en publicaciones
        $this->logger->logSecurityEvent('item_webhook_processed', [
            'item_id' => $itemId,
            'user_id' => $userId
        ]);

        // Aquí puedes implementar lógica específica
        // - Actualizar caché
        // - Notificar a otros sistemas
        // - Actualizar base de datos

        return [
            'action' => 'item_updated',
            'item_id' => $itemId,
            'user_id' => $userId
        ];
    }

    private function handleQuestionWebhook(string $questionId, string $userId): array {
        // Procesar nuevas preguntas
        $this->logger->logSecurityEvent('question_webhook_processed', [
            'question_id' => $questionId,
            'user_id' => $userId
        ]);

        // Implementar auto-respuesta o notificación
        return [
            'action' => 'question_received',
            'question_id' => $questionId,
            'user_id' => $userId
        ];
    }

    private function handleOrderWebhook(string $orderId, string $userId): array {
        // Procesar cambios en órdenes
        $this->logger->logSecurityEvent('order_webhook_processed', [
            'order_id' => $orderId,
            'user_id' => $userId
        ]);

        // Actualizar inventario, enviar confirmaciones, etc.
        return [
            'action' => 'order_updated',
            'order_id' => $orderId,
            'user_id' => $userId
        ];
    }

    private function handlePaymentWebhook(string $paymentId, string $userId): array {
        // Procesar cambios en pagos
        $this->logger->logSecurityEvent('payment_webhook_processed', [
            'payment_id' => $paymentId,
            'user_id' => $userId
        ]);

        // Actualizar estado de órdenes, enviar facturas, etc.
        return [
            'action' => 'payment_updated',
            'payment_id' => $paymentId,
            'user_id' => $userId
        ];
    }

    private function handleMessageWebhook(string $messageId, string $userId): array {
        // Procesar nuevos mensajes
        $this->logger->logSecurityEvent('message_webhook_processed', [
            'message_id' => $messageId,
            'user_id' => $userId
        ]);

        // Auto-respuesta, notificaciones, etc.
        return [
            'action' => 'message_received',
            'message_id' => $messageId,
            'user_id' => $userId
        ];
    }
}

// webhook.php
$logger = new MeliLogger();
$webhookHandler = new WebhookHandler('tu_webhook_secret', $logger);

$result = $webhookHandler->handleWebhook();

if ($result['success']) {
    http_response_code(200);
    echo json_encode(['status' => 'ok']);
} else {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => $result['error']]);
}
```

## 2. Procesamiento en Lote

### Batch Processor

```php
<?php
// BatchProcessor.php

use Tepuilabs\MeliServices\MeliServices;
use Tepuilabs\MeliServices\Exceptions\GenericException;

class BatchProcessor {
    private MeliServices $meli;
    private string $accessToken;
    private MeliLogger $logger;
    private int $batchSize;
    private int $delayBetweenBatches;

    public function __construct(MeliServices $meli, string $accessToken, MeliLogger $logger, int $batchSize = 10, int $delayBetweenBatches = 1000) {
        $this->meli = $meli;
        $this->accessToken = $accessToken;
        $this->logger = $logger;
        $this->batchSize = $batchSize;
        $this->delayBetweenBatches = $delayBetweenBatches;
    }

    public function processItems(array $itemIds, callable $processor): array {
        $results = [];
        $batches = array_chunk($itemIds, $this->batchSize);

        foreach ($batches as $batchIndex => $batch) {
            $this->logger->logSecurityEvent('batch_processing_started', [
                'batch_index' => $batchIndex,
                'batch_size' => count($batch),
                'total_batches' => count($batches)
            ]);

            $batchResults = $this->processBatch($batch, $processor);
            $results = array_merge($results, $batchResults);

            // Delay entre lotes para evitar rate limiting
            if ($batchIndex < count($batches) - 1) {
                usleep($this->delayBetweenBatches * 1000);
            }
        }

        return $results;
    }

    private function processBatch(array $itemIds, callable $processor): array {
        $results = [];

        foreach ($itemIds as $itemId) {
            try {
                $result = $processor($itemId);
                $results[] = [
                    'item_id' => $itemId,
                    'success' => true,
                    'result' => $result
                ];

            } catch (GenericException $e) {
                $this->logger->logSecurityEvent('batch_item_error', [
                    'item_id' => $itemId,
                    'error' => $e->getMessage()
                ], 'error');

                $results[] = [
                    'item_id' => $itemId,
                    'success' => false,
                    'error' => $e->getMessage()
                ];
            }
        }

        return $results;
    }

    public function updateItemsBatch(array $items): array {
        return $this->processItems(array_column($items, 'id'), function($itemId) {
            $item = $this->meli->get("/items/{$itemId}", $this->accessToken);

            // Actualizar precio (ejemplo)
            $newPrice = $item['price'] * 1.1; // Aumentar 10%

            return $this->meli->put("/items/{$itemId}", $this->accessToken, [
                'price' => $newPrice
            ]);
        });
    }

    public function createItemsBatch(array $itemData): array {
        $results = [];

        foreach ($itemData as $data) {
            try {
                $result = $this->meli->post('/items', $this->accessToken, $data);
                $results[] = [
                    'success' => true,
                    'item_id' => $result['id'],
                    'result' => $result
                ];

            } catch (GenericException $e) {
                $results[] = [
                    'success' => false,
                    'error' => $e->getMessage(),
                    'data' => $data
                ];
            }
        }

        return $results;
    }

    public function deleteItemsBatch(array $itemIds): array {
        return $this->processItems($itemIds, function($itemId) {
            return $this->meli->delete("/items/{$itemId}", $this->accessToken);
        });
    }

    public function getItemsBatch(array $itemIds): array {
        return $this->processItems($itemIds, function($itemId) {
            return $this->meli->get("/items/{$itemId}", $this->accessToken);
        });
    }
}

// Uso
$batchProcessor = new BatchProcessor($meli, $accessToken, $logger, 5, 2000);

// Actualizar precios en lote
$itemIds = ['MLA1234567890', 'MLA1234567891', 'MLA1234567892'];
$results = $batchProcessor->updateItemsBatch($itemIds);

echo "📦 Resultados del procesamiento en lote:\n";
foreach ($results as $result) {
    if ($result['success']) {
        echo "✅ Item {$result['item_id']}: Actualizado\n";
    } else {
        echo "❌ Item {$result['item_id']}: {$result['error']}\n";
    }
}
```

## 3. Caché y Optimización

### Cache Manager

```php
<?php
// CacheManager.php

class CacheManager {
    private string $cacheDir;
    private int $defaultTtl;
    private MeliLogger $logger;

    public function __construct(string $cacheDir = 'cache', int $defaultTtl = 3600, MeliLogger $logger = null) {
        $this->cacheDir = $cacheDir;
        $this->defaultTtl = $defaultTtl;
        $this->logger = $logger;

        if (!is_dir($cacheDir)) {
            mkdir($cacheDir, 0755, true);
        }
    }

    public function get(string $key) {
        $cacheFile = $this->getCacheFile($key);

        if (!file_exists($cacheFile)) {
            return null;
        }

        $data = json_decode(file_get_contents($cacheFile), true);
        if (!$data) {
            return null;
        }

        // Verificar expiración
        if (time() > $data['expires']) {
            unlink($cacheFile);
            return null;
        }

        $this->logger?->logSecurityEvent('cache_hit', ['key' => $key]);
        return $data['value'];
    }

    public function set(string $key, $value, int $ttl = null): bool {
        $cacheFile = $this->getCacheFile($key);
        $ttl = $ttl ?? $this->defaultTtl;

        $data = [
            'key' => $key,
            'value' => $value,
            'created' => time(),
            'expires' => time() + $ttl
        ];

        $result = file_put_contents($cacheFile, json_encode($data));

        if ($result !== false) {
            $this->logger?->logSecurityEvent('cache_set', ['key' => $key, 'ttl' => $ttl]);
        }

        return $result !== false;
    }

    public function delete(string $key): bool {
        $cacheFile = $this->getCacheFile($key);

        if (file_exists($cacheFile)) {
            $result = unlink($cacheFile);
            $this->logger?->logSecurityEvent('cache_delete', ['key' => $key]);
            return $result;
        }

        return true;
    }

    public function clear(): bool {
        $files = glob($this->cacheDir . '/*.cache');

        foreach ($files as $file) {
            unlink($file);
        }

        $this->logger?->logSecurityEvent('cache_clear', ['files_deleted' => count($files)]);
        return true;
    }

    public function getStats(): array {
        $files = glob($this->cacheDir . '/*.cache');
        $totalSize = 0;
        $expiredFiles = 0;
        $validFiles = 0;

        foreach ($files as $file) {
            $totalSize += filesize($file);
            $data = json_decode(file_get_contents($file), true);

            if ($data && time() > $data['expires']) {
                $expiredFiles++;
            } else {
                $validFiles++;
            }
        }

        return [
            'total_files' => count($files),
            'valid_files' => $validFiles,
            'expired_files' => $expiredFiles,
            'total_size' => $totalSize,
            'cache_dir' => $this->cacheDir
        ];
    }

    private function getCacheFile(string $key): string {
        $hash = hash('sha256', $key);
        return $this->cacheDir . '/' . $hash . '.cache';
    }
}

// Cached Meli Services
class CachedMeliServices extends MeliServices {
    private CacheManager $cache;
    private array $cacheableEndpoints = [
        '/users/me',
        '/sites/MLA/categories',
        '/currencies'
    ];

    public function __construct(MeliConfig $config, CacheManager $cache) {
        parent::__construct($config);
        $this->cache = $cache;
    }

    public function get(string $endpoint, string $accessToken): array {
        // Verificar si el endpoint es cacheable
        if ($this->isCacheable($endpoint)) {
            $cacheKey = $this->generateCacheKey($endpoint, $accessToken);
            $cached = $this->cache->get($cacheKey);

            if ($cached !== null) {
                return $cached;
            }
        }

        // Hacer llamada a la API
        $result = parent::get($endpoint, $accessToken);

        // Guardar en caché si es cacheable
        if ($this->isCacheable($endpoint)) {
            $cacheKey = $this->generateCacheKey($endpoint, $accessToken);
            $this->cache->set($cacheKey, $result, 1800); // 30 minutos
        }

        return $result;
    }

    private function isCacheable(string $endpoint): bool {
        foreach ($this->cacheableEndpoints as $cacheableEndpoint) {
            if (strpos($endpoint, $cacheableEndpoint) === 0) {
                return true;
            }
        }
        return false;
    }

    private function generateCacheKey(string $endpoint, string $accessToken): string {
        return 'meli_' . hash('sha256', $endpoint . '_' . substr($accessToken, 0, 10));
    }
}

// Uso
$cacheManager = new CacheManager('cache/meli', 1800, $logger);
$cachedMeli = new CachedMeliServices($config, $cacheManager);

// Las llamadas a endpoints cacheables serán más rápidas
$profile = $cachedMeli->get('/users/me', $accessToken);
$categories = $cachedMeli->get('/sites/MLA/categories', $accessToken);

// Estadísticas del caché
$stats = $cacheManager->getStats();
echo "📊 Estadísticas del caché:\n";
echo "Archivos totales: " . $stats['total_files'] . "\n";
echo "Archivos válidos: " . $stats['valid_files'] . "\n";
echo "Archivos expirados: " . $stats['expired_files'] . "\n";
echo "Tamaño total: " . round($stats['total_size'] / 1024, 2) . " KB\n";
```

## 4. Integración con Frameworks

### Laravel Integration

```php
<?php
// LaravelMeliService.php

namespace App\Services;

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class LaravelMeliService {
    private MeliServices $meli;
    private string $accessToken;

    public function __construct() {
        $config = MeliConfig::fromArray([
            'client_id' => config('services.mercadolibre.client_id'),
            'client_secret' => config('services.mercadolibre.client_secret'),
            'redirect_uri' => config('services.mercadolibre.redirect_uri')
        ]);

        $this->meli = new MeliServices($config);
        $this->accessToken = session('meli_access_token');
    }

    public function get(string $endpoint, bool $useCache = true): array {
        if ($useCache) {
            $cacheKey = 'meli_' . md5($endpoint . '_' . substr($this->accessToken, 0, 10));

            return Cache::remember($cacheKey, 1800, function() use ($endpoint) {
                return $this->meli->get($endpoint, $this->accessToken);
            });
        }

        return $this->meli->get($endpoint, $this->accessToken);
    }

    public function post(string $endpoint, array $data): array {
        return $this->meli->post($endpoint, $this->accessToken, $data);
    }

    public function put(string $endpoint, array $data): array {
        return $this->meli->put($endpoint, $this->accessToken, $data);
    }

    public function delete(string $endpoint): array {
        return $this->meli->delete($endpoint, $this->accessToken);
    }

    public function getUserProfile(): array {
        return $this->get('/users/me');
    }

    public function getUserItems(int $limit = 50): array {
        $userId = session('meli_user_id');
        return $this->get("/users/{$userId}/items/search?limit={$limit}");
    }

    public function createItem(array $itemData): array {
        return $this->post('/items', $itemData);
    }

    public function updateItem(string $itemId, array $updateData): array {
        return $this->put("/items/{$itemId}", $updateData);
    }

    public function deleteItem(string $itemId): array {
        return $this->delete("/items/{$itemId}");
    }
}

// Laravel Controller
class MercadoLibreController extends Controller {
    private LaravelMeliService $meliService;

    public function __construct(LaravelMeliService $meliService) {
        $this->meliService = $meliService;
    }

    public function profile() {
        try {
            $profile = $this->meliService->getUserProfile();
            return response()->json($profile);
        } catch (\Exception $e) {
            Log::error('Meli API Error: ' . $e->getMessage());
            return response()->json(['error' => 'Error al obtener perfil'], 500);
        }
    }

    public function items() {
        try {
            $items = $this->meliService->getUserItems();
            return response()->json($items);
        } catch (\Exception $e) {
            Log::error('Meli API Error: ' . $e->getMessage());
            return response()->json(['error' => 'Error al obtener items'], 500);
        }
    }

    public function createItem(Request $request) {
        try {
            $itemData = $request->validate([
                'title' => 'required|string|max:60',
                'category_id' => 'required|string',
                'price' => 'required|numeric|min:0',
                'currency_id' => 'required|string',
                'available_quantity' => 'required|integer|min:1',
                'condition' => 'required|in:new,used'
            ]);

            $result = $this->meliService->createItem($itemData);
            return response()->json($result, 201);
        } catch (\Exception $e) {
            Log::error('Meli API Error: ' . $e->getMessage());
            return response()->json(['error' => 'Error al crear item'], 500);
        }
    }
}

// config/services.php
return [
    'mercadolibre' => [
        'client_id' => env('MELI_CLIENT_ID'),
        'client_secret' => env('MELI_CLIENT_SECRET'),
        'redirect_uri' => env('MELI_REDIRECT_URI'),
    ],
];

// .env
MELI_CLIENT_ID=tu_client_id
MELI_CLIENT_SECRET=tu_client_secret
MELI_REDIRECT_URI=https://tuapp.com/meli/callback
```

### Symfony Integration

```php
<?php
// SymfonyMeliService.php

namespace App\Service;

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;
use Symfony\Component\Cache\CacheItem;
use Symfony\Contracts\Cache\CacheInterface;
use Psr\Log\LoggerInterface;

class SymfonyMeliService {
    private MeliServices $meli;
    private CacheInterface $cache;
    private LoggerInterface $logger;
    private string $accessToken;

    public function __construct(
        CacheInterface $cache,
        LoggerInterface $logger,
        string $clientId,
        string $clientSecret,
        string $redirectUri
    ) {
        $config = MeliConfig::fromArray([
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'redirect_uri' => $redirectUri
        ]);

        $this->meli = new MeliServices($config);
        $this->cache = $cache;
        $this->logger = $logger;
    }

    public function setAccessToken(string $accessToken): void {
        $this->accessToken = $accessToken;
    }

    public function get(string $endpoint, bool $useCache = true): array {
        if ($useCache) {
            $cacheKey = 'meli_' . md5($endpoint . '_' . substr($this->accessToken, 0, 10));

            return $this->cache->get($cacheKey, function(CacheItem $item) use ($endpoint) {
                $item->expiresAfter(1800); // 30 minutos
                return $this->meli->get($endpoint, $this->accessToken);
            });
        }

        return $this->meli->get($endpoint, $this->accessToken);
    }

    public function post(string $endpoint, array $data): array {
        return $this->meli->post($endpoint, $this->accessToken, $data);
    }

    public function put(string $endpoint, array $data): array {
        return $this->meli->put($endpoint, $this->accessToken, $data);
    }

    public function delete(string $endpoint): array {
        return $this->meli->delete($endpoint, $this->accessToken);
    }
}

// services.yaml
services:
    App\Service\SymfonyMeliService:
        arguments:
            $cache: '@cache.app'
            $logger: '@logger'
            $clientId: '%env(MELI_CLIENT_ID)%'
            $clientSecret: '%env(MELI_CLIENT_SECRET)%'
            $redirectUri: '%env(MELI_REDIRECT_URI)%'

// .env.local
MELI_CLIENT_ID=tu_client_id
MELI_CLIENT_SECRET=tu_client_secret
MELI_REDIRECT_URI=https://tuapp.com/meli/callback
```

## 5. Monitoreo Avanzado

### Advanced Monitoring

```php
<?php
// AdvancedMonitor.php

class AdvancedMonitor {
    private MeliLogger $logger;
    private array $metrics = [];
    private array $alerts = [];
    private array $thresholds;

    public function __construct(MeliLogger $logger, array $thresholds = []) {
        $this->logger = $logger;
        $this->thresholds = array_merge([
            'error_rate' => 5.0,
            'response_time' => 2000,
            'api_calls_per_minute' => 100,
            'consecutive_failures' => 3
        ], $thresholds);
    }

    public function recordApiCall(string $endpoint, float $duration, bool $success, int $statusCode): void {
        $timestamp = time();
        $minute = floor($timestamp / 60);

        // Métricas por minuto
        if (!isset($this->metrics[$minute])) {
            $this->metrics[$minute] = [
                'calls' => 0,
                'successful' => 0,
                'failed' => 0,
                'total_duration' => 0,
                'endpoints' => []
            ];
        }

        $this->metrics[$minute]['calls']++;
        $this->metrics[$minute]['total_duration'] += $duration;

        if ($success) {
            $this->metrics[$minute]['successful']++;
        } else {
            $this->metrics[$minute]['failed']++;
        }

        // Métricas por endpoint
        if (!isset($this->metrics[$minute]['endpoints'][$endpoint])) {
            $this->metrics[$minute]['endpoints'][$endpoint] = [
                'calls' => 0,
                'successful' => 0,
                'failed' => 0,
                'total_duration' => 0
            ];
        }

        $this->metrics[$minute]['endpoints'][$endpoint]['calls']++;
        $this->metrics[$minute]['endpoints'][$endpoint]['total_duration'] += $duration;

        if ($success) {
            $this->metrics[$minute]['endpoints'][$endpoint]['successful']++;
        } else {
            $this->metrics[$minute]['endpoints'][$endpoint]['failed']++;
        }

        // Verificar alertas
        $this->checkAlerts($minute);

        // Limpiar métricas antiguas (más de 1 hora)
        $this->cleanOldMetrics();
    }

    private function checkAlerts(int $minute): void {
        $metrics = $this->metrics[$minute] ?? [];

        if (empty($metrics)) {
            return;
        }

        // Verificar tasa de errores
        $errorRate = $metrics['calls'] > 0 ? ($metrics['failed'] / $metrics['calls']) * 100 : 0;
        if ($errorRate > $this->thresholds['error_rate']) {
            $this->triggerAlert('high_error_rate', [
                'error_rate' => $errorRate,
                'threshold' => $this->thresholds['error_rate'],
                'minute' => $minute
            ]);
        }

        // Verificar tiempo de respuesta promedio
        $avgResponseTime = $metrics['calls'] > 0 ? $metrics['total_duration'] / $metrics['calls'] : 0;
        if ($avgResponseTime > $this->thresholds['response_time']) {
            $this->triggerAlert('slow_response_time', [
                'avg_response_time' => $avgResponseTime,
                'threshold' => $this->thresholds['response_time'],
                'minute' => $minute
            ]);
        }

        // Verificar número de llamadas por minuto
        if ($metrics['calls'] > $this->thresholds['api_calls_per_minute']) {
            $this->triggerAlert('high_api_calls', [
                'calls_per_minute' => $metrics['calls'],
                'threshold' => $this->thresholds['api_calls_per_minute'],
                'minute' => $minute
            ]);
        }
    }

    private function triggerAlert(string $type, array $data): void {
        $alert = [
            'type' => $type,
            'timestamp' => date('Y-m-d H:i:s'),
            'data' => $data
        ];

        $this->alerts[] = $alert;
        $this->logger->logSecurityEvent('monitoring_alert', $alert, 'high');

        // Enviar notificación
        $this->sendNotification($alert);
    }

    private function sendNotification(array $alert): void {
        $subject = "[Meli Monitor] Alert: {$alert['type']}";
        $body = json_encode($alert, JSON_PRETTY_PRINT);

        // Implementar envío de notificaciones
        // mail('admin@example.com', $subject, $body);
    }

    private function cleanOldMetrics(): void {
        $currentMinute = floor(time() / 60);
        $cutoffMinute = $currentMinute - 60; // Mantener solo 1 hora

        foreach ($this->metrics as $minute => $data) {
            if ($minute < $cutoffMinute) {
                unset($this->metrics[$minute]);
            }
        }
    }

    public function getMetrics(): array {
        $currentMinute = floor(time() / 60);
        $currentMetrics = $this->metrics[$currentMinute] ?? [];

        return [
            'current_minute' => $currentMetrics,
            'last_hour' => $this->getLastHourMetrics(),
            'alerts' => $this->alerts
        ];
    }

    private function getLastHourMetrics(): array {
        $currentMinute = floor(time() / 60);
        $totalCalls = 0;
        $totalSuccessful = 0;
        $totalFailed = 0;
        $totalDuration = 0;

        for ($i = 0; $i < 60; $i++) {
            $minute = $currentMinute - $i;
            $metrics = $this->metrics[$minute] ?? [];

            $totalCalls += $metrics['calls'] ?? 0;
            $totalSuccessful += $metrics['successful'] ?? 0;
            $totalFailed += $metrics['failed'] ?? 0;
            $totalDuration += $metrics['total_duration'] ?? 0;
        }

        return [
            'total_calls' => $totalCalls,
            'total_successful' => $totalSuccessful,
            'total_failed' => $totalFailed,
            'avg_response_time' => $totalCalls > 0 ? $totalDuration / $totalCalls : 0,
            'error_rate' => $totalCalls > 0 ? ($totalFailed / $totalCalls) * 100 : 0
        ];
    }

    public function getDashboardData(): array {
        $metrics = $this->getMetrics();
        $currentMetrics = $metrics['current_minute'];
        $lastHour = $metrics['last_hour'];

        return [
            'current_minute' => [
                'calls' => $currentMetrics['calls'] ?? 0,
                'successful' => $currentMetrics['successful'] ?? 0,
                'failed' => $currentMetrics['failed'] ?? 0,
                'avg_response_time' => $currentMetrics['calls'] > 0 ?
                    $currentMetrics['total_duration'] / $currentMetrics['calls'] : 0
            ],
            'last_hour' => $lastHour,
            'alerts_count' => count($this->alerts),
            'recent_alerts' => array_slice($this->alerts, -5)
        ];
    }
}

// Uso
$monitor = new AdvancedMonitor($logger, [
    'error_rate' => 3.0,
    'response_time' => 1500,
    'api_calls_per_minute' => 50
]);

// Registrar llamadas a la API
$monitor->recordApiCall('/users/me', 0.5, true, 200);
$monitor->recordApiCall('/items/search', 2.1, false, 429);
$monitor->recordApiCall('/categories', 0.3, true, 200);

// Obtener datos del dashboard
$dashboard = $monitor->getDashboardData();
echo "📊 Dashboard de Monitoreo:\n";
echo "Llamadas este minuto: " . $dashboard['current_minute']['calls'] . "\n";
echo "Tiempo promedio: " . round($dashboard['current_minute']['avg_response_time'], 2) . "ms\n";
echo "Tasa de error (última hora): " . round($dashboard['last_hour']['error_rate'], 2) . "%\n";
echo "Alertas: " . $dashboard['alerts_count'] . "\n";
```

## Resumen

En este capítulo final has aprendido:

- ✅ Implementación de webhooks para eventos en tiempo real
- ✅ Procesamiento en lote para operaciones masivas
- ✅ Sistema de caché para optimizar rendimiento
- ✅ Integración con frameworks populares (Laravel, Symfony)
- ✅ Monitoreo avanzado con métricas y alertas
- ✅ Técnicas de optimización y escalabilidad
- ✅ Casos de uso complejos y especializados

## 🎉 ¡Felicidades!

Has completado toda la documentación de la librería `mini-meli`. Ahora tienes:

- ✅ **Conocimiento completo** de todas las funcionalidades
- ✅ **Ejemplos prácticos** para cada caso de uso
- ✅ **Mejores prácticas** de seguridad y rendimiento
- ✅ **Técnicas avanzadas** para aplicaciones en producción
- ✅ **Integración** con frameworks modernos

¡Estás listo para construir aplicaciones robustas y escalables con Mercado Libre! 🚀
