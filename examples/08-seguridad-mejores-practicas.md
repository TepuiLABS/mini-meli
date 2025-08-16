# 08. Seguridad y Mejores Prácticas

## Introducción

La seguridad es fundamental cuando trabajas con APIs de terceros y datos de usuarios. En este capítulo aprenderás las mejores prácticas de seguridad para usar la librería `mini-meli` en producción, incluyendo almacenamiento seguro de tokens, validación de entrada, protección CSRF y auditoría de seguridad.

## Principios de Seguridad

### 🔒 Confidencialidad
- Proteger tokens y credenciales
- Encriptar datos sensibles
- Usar HTTPS siempre

### 🔐 Integridad
- Validar todas las entradas
- Verificar firmas y hashes
- Proteger contra manipulación

### ✅ Disponibilidad
- Manejar errores gracefully
- Implementar fallbacks
- Monitorear la aplicación

## 1. Almacenamiento Seguro de Tokens

### ❌ Prácticas Inseguras

```php
// ❌ MAL: Almacenar en texto plano
$_SESSION['access_token'] = $token;
$_SESSION['refresh_token'] = $refreshToken;

// ❌ MAL: Guardar en archivo de texto
file_put_contents('tokens.txt', $token);

// ❌ MAL: Usar cookies inseguras
setcookie('access_token', $token);
```

### ✅ Prácticas Seguras

```php
<?php
// TokenManager.php

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;

class SecureTokenManager {
    private Key $encryptionKey;
    private string $sessionPrefix = 'meli_secure_';

    public function __construct(string $encryptionKeyPath = null) {
        if ($encryptionKeyPath && file_exists($encryptionKeyPath)) {
            $this->encryptionKey = Key::loadFromAsciiSafeString(file_get_contents($encryptionKeyPath));
        } else {
            $this->encryptionKey = Key::createNewRandomKey();
            if ($encryptionKeyPath) {
                file_put_contents($encryptionKeyPath, $this->encryptionKey->saveToAsciiSafeString());
            }
        }
    }

    public function storeTokens(array $tokens): void {
        session_start();

        // Encriptar tokens antes de almacenar
        $encryptedTokens = [];

        foreach ($tokens as $key => $value) {
            if (in_array($key, ['access_token', 'refresh_token'])) {
                $encryptedTokens[$key] = Crypto::encrypt($value, $this->encryptionKey);
            } else {
                $encryptedTokens[$key] = $value;
            }
        }

        // Almacenar con prefijo de seguridad
        $_SESSION[$this->sessionPrefix . 'tokens'] = $encryptedTokens;
        $_SESSION[$this->sessionPrefix . 'created'] = time();
    }

    public function getTokens(): ?array {
        session_start();

        if (!isset($_SESSION[$this->sessionPrefix . 'tokens'])) {
            return null;
        }

        $encryptedTokens = $_SESSION[$this->sessionPrefix . 'tokens'];
        $tokens = [];

        foreach ($encryptedTokens as $key => $value) {
            if (in_array($key, ['access_token', 'refresh_token'])) {
                try {
                    $tokens[$key] = Crypto::decrypt($value, $this->encryptionKey);
                } catch (Exception $e) {
                    // Token corrupto, limpiar sesión
                    $this->clearTokens();
                    return null;
                }
            } else {
                $tokens[$key] = $value;
            }
        }

        return $tokens;
    }

    public function getAccessToken(): ?string {
        $tokens = $this->getTokens();
        return $tokens['access_token'] ?? null;
    }

    public function getRefreshToken(): ?string {
        $tokens = $this->getTokens();
        return $tokens['refresh_token'] ?? null;
    }

    public function clearTokens(): void {
        session_start();
        unset($_SESSION[$this->sessionPrefix . 'tokens']);
        unset($_SESSION[$this->sessionPrefix . 'created']);
    }

    public function isTokenExpired(): bool {
        $tokens = $this->getTokens();
        if (!$tokens) {
            return true;
        }

        $created = $_SESSION[$this->sessionPrefix . 'created'] ?? 0;
        $expiresIn = $tokens['expires_in'] ?? 0;

        return (time() - $created) >= $expiresIn;
    }
}

// Uso
$tokenManager = new SecureTokenManager('config/encryption.key');

// Almacenar tokens de forma segura
$tokenManager->storeTokens([
    'access_token' => $response->getAccessToken(),
    'refresh_token' => $response->getRefreshToken(),
    'expires_in' => $response->getExpiresIn(),
    'user_id' => $response->getUserId()
]);

// Obtener tokens de forma segura
$accessToken = $tokenManager->getAccessToken();
```

## 2. Validación de Entrada

### Clase InputValidator

```php
<?php
// InputValidator.php

class InputValidator {
    private array $errors = [];

    public function validateClientId(string $clientId): bool {
        if (empty($clientId)) {
            $this->errors[] = 'Client ID no puede estar vacío';
            return false;
        }

        if (!preg_match('/^\d+$/', $clientId)) {
            $this->errors[] = 'Client ID debe ser numérico';
            return false;
        }

        if (strlen($clientId) < 10 || strlen($clientId) > 20) {
            $this->errors[] = 'Client ID debe tener entre 10 y 20 dígitos';
            return false;
        }

        return true;
    }

    public function validateRedirectUri(string $redirectUri): bool {
        if (empty($redirectUri)) {
            $this->errors[] = 'Redirect URI no puede estar vacío';
            return false;
        }

        if (!filter_var($redirectUri, FILTER_VALIDATE_URL)) {
            $this->errors[] = 'Redirect URI debe ser una URL válida';
            return false;
        }

        // Verificar que sea HTTPS en producción
        if (strpos($redirectUri, 'https://') !== 0 && !$this->isLocalhost($redirectUri)) {
            $this->errors[] = 'Redirect URI debe usar HTTPS en producción';
            return false;
        }

        return true;
    }

    public function validateState(string $state): bool {
        if (empty($state)) {
            $this->errors[] = 'State no puede estar vacío';
            return false;
        }

        if (!preg_match('/^[a-zA-Z0-9]{16,}$/', $state)) {
            $this->errors[] = 'State debe ser alfanumérico y tener al menos 16 caracteres';
            return false;
        }

        return true;
    }

    public function validateCode(string $code): bool {
        if (empty($code)) {
            $this->errors[] = 'Código de autorización no puede estar vacío';
            return false;
        }

        if (!preg_match('/^[a-zA-Z0-9_-]{20,}$/', $code)) {
            $this->errors[] = 'Código de autorización inválido';
            return false;
        }

        return true;
    }

    public function validateScopes(array $scopes): bool {
        $validScopes = ['read', 'write', 'offline_access'];

        foreach ($scopes as $scope) {
            if (!in_array($scope, $validScopes)) {
                $this->errors[] = "Scope inválido: {$scope}";
                return false;
            }
        }

        return true;
    }

    public function validateSiteId(string $siteId): bool {
        $validSites = ['MLA', 'MLB', 'MLM', 'MLC', 'MCO', 'MPE', 'MLU', 'MLV'];

        if (!in_array($siteId, $validSites)) {
            $this->errors[] = "Site ID inválido: {$siteId}";
            return false;
        }

        return true;
    }

    private function isLocalhost(string $url): bool {
        $host = parse_url($url, PHP_URL_HOST);
        return in_array($host, ['localhost', '127.0.0.1', '::1']);
    }

    public function sanitizeString(string $input): string {
        return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
    }

    public function sanitizeArray(array $input): array {
        $sanitized = [];

        foreach ($input as $key => $value) {
            if (is_string($value)) {
                $sanitized[$key] = $this->sanitizeString($value);
            } elseif (is_array($value)) {
                $sanitized[$key] = $this->sanitizeArray($value);
            } else {
                $sanitized[$key] = $value;
            }
        }

        return $sanitized;
    }

    public function getErrors(): array {
        return $this->errors;
    }

    public function hasErrors(): bool {
        return !empty($this->errors);
    }

    public function clearErrors(): void {
        $this->errors = [];
    }
}

// Uso
$validator = new InputValidator();

// Validar configuración
$config = [
    'client_id' => $_POST['client_id'] ?? '',
    'redirect_uri' => $_POST['redirect_uri'] ?? '',
    'scopes' => $_POST['scopes'] ?? []
];

$isValid = true;
$isValid &= $validator->validateClientId($config['client_id']);
$isValid &= $validator->validateRedirectUri($config['redirect_uri']);
$isValid &= $validator->validateScopes($config['scopes']);

if (!$isValid) {
    echo "❌ Errores de validación:\n";
    foreach ($validator->getErrors() as $error) {
        echo "- {$error}\n";
    }
    exit;
}

// Sanitizar entrada
$sanitizedConfig = $validator->sanitizeArray($config);
```

## 3. Protección CSRF

### CSRF Protection Manager

```php
<?php
// CSRFProtection.php

class CSRFProtection {
    private string $sessionKey = 'csrf_token';
    private int $tokenLength = 32;

    public function generateToken(): string {
        session_start();

        $token = bin2hex(random_bytes($this->tokenLength));
        $_SESSION[$this->sessionKey] = $token;

        return $token;
    }

    public function getToken(): ?string {
        session_start();
        return $_SESSION[$this->sessionKey] ?? null;
    }

    public function validateToken(string $token): bool {
        session_start();

        $storedToken = $_SESSION[$this->sessionKey] ?? null;

        if (!$storedToken || !$token) {
            return false;
        }

        // Comparación segura contra timing attacks
        return hash_equals($storedToken, $token);
    }

    public function clearToken(): void {
        session_start();
        unset($_SESSION[$this->sessionKey]);
    }

    public function getTokenField(): string {
        $token = $this->getToken();
        return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">';
    }

    public function validateRequest(): bool {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

        // Solo validar métodos que modifican datos
        if (!in_array($method, ['POST', 'PUT', 'DELETE', 'PATCH'])) {
            return true;
        }

        $token = $_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '';
        return $this->validateToken($token);
    }
}

// Uso
$csrf = new CSRFProtection();

// En formularios
echo '<form method="post">';
echo $csrf->getTokenField();
echo '<input type="text" name="client_id">';
echo '<button type="submit">Enviar</button>';
echo '</form>';

// Validar en el procesamiento
if (!$csrf->validateRequest()) {
    die("❌ Error CSRF: Token inválido");
}
```

## 4. Auditoría de Seguridad

### Security Auditor

```php
<?php
// SecurityAuditor.php

class SecurityAuditor {
    private string $logFile;
    private array $sensitiveOperations = [
        'token_refresh',
        'authorization_revoke',
        'user_data_access',
        'admin_operation'
    ];

    public function __construct(string $logFile = 'logs/security.log') {
        $this->logFile = $logFile;

        $logDir = dirname($logFile);
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
    }

    public function logSecurityEvent(string $event, array $data = [], string $severity = 'info'): void {
        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'event' => $event,
            'severity' => $severity,
            'ip_address' => $this->getClientIP(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'session_id' => session_id(),
            'data' => $this->sanitizeLogData($data)
        ];

        $logLine = json_encode($logEntry) . "\n";
        file_put_contents($this->logFile, $logLine, FILE_APPEND | LOCK_EX);
    }

    public function logTokenOperation(string $operation, array $tokenData = []): void {
        $sanitizedData = [
            'operation' => $operation,
            'user_id' => $tokenData['user_id'] ?? null,
            'token_preview' => isset($tokenData['access_token']) ?
                substr($tokenData['access_token'], 0, 10) . '...' : null,
            'expires_in' => $tokenData['expires_in'] ?? null
        ];

        $this->logSecurityEvent("token_{$operation}", $sanitizedData, 'info');
    }

    public function logAuthorizationAttempt(string $siteId, bool $success, string $error = null): void {
        $data = [
            'site_id' => $siteId,
            'success' => $success,
            'error' => $error
        ];

        $severity = $success ? 'info' : 'warning';
        $this->logSecurityEvent('authorization_attempt', $data, $severity);
    }

    public function logDataAccess(string $endpoint, array $params = [], bool $success = true): void {
        $data = [
            'endpoint' => $endpoint,
            'params' => $this->sanitizeParams($params),
            'success' => $success
        ];

        $severity = $success ? 'info' : 'warning';
        $this->logSecurityEvent('data_access', $data, $severity);
    }

    public function logSuspiciousActivity(string $activity, array $details = []): void {
        $this->logSecurityEvent('suspicious_activity', $details, 'high');

        // Enviar alerta inmediata
        $this->sendSecurityAlert($activity, $details);
    }

    private function getClientIP(): string {
        $ipKeys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];

        foreach ($ipKeys as $key) {
            if (isset($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }

    private function sanitizeLogData(array $data): array {
        $sensitiveKeys = ['access_token', 'refresh_token', 'client_secret', 'password'];

        foreach ($sensitiveKeys as $key) {
            if (isset($data[$key])) {
                $data[$key] = substr($data[$key], 0, 10) . '...';
            }
        }

        return $data;
    }

    private function sanitizeParams(array $params): array {
        return $this->sanitizeLogData($params);
    }

    private function sendSecurityAlert(string $activity, array $details): void {
        $subject = "[SECURITY ALERT] Suspicious activity detected";
        $body = "Activity: {$activity}\n";
        $body .= "Details: " . json_encode($details, JSON_PRETTY_PRINT) . "\n";
        $body .= "IP: " . $this->getClientIP() . "\n";
        $body .= "Time: " . date('Y-m-d H:i:s') . "\n";

        // Enviar email de alerta
        // mail('security@example.com', $subject, $body);

        // O enviar a Slack/Discord
        // $this->sendSlackAlert($subject, $body);
    }

    public function getSecurityReport(): array {
        $report = [
            'total_events' => 0,
            'events_by_severity' => [],
            'recent_suspicious' => [],
            'token_operations' => []
        ];

        if (!file_exists($this->logFile)) {
            return $report;
        }

        $lines = file($this->logFile);
        $report['total_events'] = count($lines);

        foreach ($lines as $line) {
            $event = json_decode($line, true);
            if ($event) {
                $severity = $event['severity'] ?? 'unknown';
                $report['events_by_severity'][$severity] =
                    ($report['events_by_severity'][$severity] ?? 0) + 1;

                // Eventos sospechosos recientes (últimas 24 horas)
                if ($event['severity'] === 'high' &&
                    strtotime($event['timestamp']) > time() - 86400) {
                    $report['recent_suspicious'][] = $event;
                }

                // Operaciones de tokens
                if (strpos($event['event'], 'token_') === 0) {
                    $report['token_operations'][] = $event;
                }
            }
        }

        return $report;
    }
}

// Uso
$auditor = new SecurityAuditor();

// Log de operaciones
$auditor->logTokenOperation('refresh', [
    'user_id' => $userId,
    'access_token' => $newToken,
    'expires_in' => 21600
]);

$auditor->logAuthorizationAttempt('MLA', true);

$auditor->logDataAccess('/users/me', [], true);

// Verificar actividad sospechosa
if ($failedAttempts > 5) {
    $auditor->logSuspiciousActivity('Multiple failed authorization attempts', [
        'attempts' => $failedAttempts,
        'ip' => $_SERVER['REMOTE_ADDR']
    ]);
}

// Generar reporte
$report = $auditor->getSecurityReport();
echo "📊 Reporte de Seguridad:\n";
echo "Total eventos: " . $report['total_events'] . "\n";
echo "Eventos por severidad: " . json_encode($report['events_by_severity']) . "\n";
echo "Actividad sospechosa reciente: " . count($report['recent_suspicious']) . "\n";
```

## 5. Configuración Segura

### Secure Configuration Manager

```php
<?php
// SecureConfig.php

class SecureConfig {
    private array $config;
    private string $configFile;
    private string $encryptionKey;

    public function __construct(string $configFile = 'config/secure.php', string $encryptionKey = null) {
        $this->configFile = $configFile;
        $this->encryptionKey = $encryptionKey ?? $this->getDefaultEncryptionKey();
        $this->loadConfig();
    }

    private function loadConfig(): void {
        if (file_exists($this->configFile)) {
            $this->config = include $this->configFile;
        } else {
            $this->config = $this->getDefaultConfig();
            $this->saveConfig();
        }
    }

    private function getDefaultConfig(): array {
        return [
            'client_id' => '',
            'client_secret' => '',
            'redirect_uri' => '',
            'scopes' => ['read', 'write', 'offline_access'],
            'security' => [
                'session_timeout' => 3600,
                'max_login_attempts' => 5,
                'lockout_duration' => 900,
                'require_https' => true,
                'csrf_protection' => true
            ],
            'logging' => [
                'enabled' => true,
                'level' => 'info',
                'file' => 'logs/app.log'
            ]
        ];
    }

    public function get(string $key, $default = null) {
        return $this->config[$key] ?? $default;
    }

    public function set(string $key, $value): void {
        $this->config[$key] = $value;
        $this->saveConfig();
    }

    public function isSecure(): bool {
        $security = $this->config['security'] ?? [];

        // Verificar HTTPS
        if ($security['require_https'] ?? true) {
            if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
                return false;
            }
        }

        // Verificar headers de seguridad
        $headers = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security'
        ];

        foreach ($headers as $header) {
            if (!isset($_SERVER["HTTP_{$header}"])) {
                return false;
            }
        }

        return true;
    }

    public function enforceSecurityHeaders(): void {
        // Headers de seguridad
        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header('X-XSS-Protection: 1; mode=block');
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\';');
        header('Referrer-Policy: strict-origin-when-cross-origin');
    }

    private function getDefaultEncryptionKey(): string {
        $keyFile = 'config/encryption.key';

        if (file_exists($keyFile)) {
            return file_get_contents($keyFile);
        }

        $key = bin2hex(random_bytes(32));
        file_put_contents($keyFile, $key);
        chmod($keyFile, 0600);

        return $key;
    }

    private function saveConfig(): void {
        $configContent = "<?php\nreturn " . var_export($this->config, true) . ";\n";
        file_put_contents($this->configFile, $configContent);
        chmod($this->configFile, 0600);
    }
}

// Uso
$secureConfig = new SecureConfig();

// Aplicar headers de seguridad
$secureConfig->enforceSecurityHeaders();

// Verificar configuración segura
if (!$secureConfig->isSecure()) {
    die("❌ Configuración de seguridad insuficiente");
}

// Obtener configuración
$clientId = $secureConfig->get('client_id');
$clientSecret = $secureConfig->get('client_secret');
```

## 6. Middleware de Seguridad

### Security Middleware

```php
<?php
// SecurityMiddleware.php

class SecurityMiddleware {
    private SecureConfig $config;
    private SecurityAuditor $auditor;
    private CSRFProtection $csrf;

    public function __construct(SecureConfig $config, SecurityAuditor $auditor, CSRFProtection $csrf) {
        $this->config = $config;
        $this->auditor = $auditor;
        $this->csrf = $csrf;
    }

    public function run(): void {
        // Aplicar headers de seguridad
        $this->config->enforceSecurityHeaders();

        // Verificar HTTPS
        if (!$this->config->isSecure()) {
            $this->auditor->logSuspiciousActivity('Insecure connection attempt');
            die("❌ Conexión insegura no permitida");
        }

        // Verificar CSRF para métodos modificadores
        if (!$this->csrf->validateRequest()) {
            $this->auditor->logSuspiciousActivity('CSRF token validation failed');
            die("❌ Error CSRF: Token inválido");
        }

        // Verificar rate limiting
        if ($this->isRateLimited()) {
            $this->auditor->logSuspiciousActivity('Rate limit exceeded');
            http_response_code(429);
            die("❌ Demasiadas solicitudes");
        }

        // Verificar sesión
        if (!$this->validateSession()) {
            $this->auditor->logSuspiciousActivity('Invalid session');
            header('Location: login.php');
            exit;
        }
    }

    private function isRateLimited(): bool {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $cacheFile = "cache/rate_limit_{$ip}.json";

        $data = [];
        if (file_exists($cacheFile)) {
            $data = json_decode(file_get_contents($cacheFile), true) ?? [];
        }

        $now = time();
        $requests = $data['requests'] ?? [];

        // Limpiar requests antiguos (últimos 60 segundos)
        $requests = array_filter($requests, function($time) use ($now) {
            return $time > $now - 60;
        });

        $requests[] = $now;

        $data['requests'] = $requests;
        file_put_contents($cacheFile, json_encode($data));

        // Límite: 100 requests por minuto
        return count($requests) > 100;
    }

    private function validateSession(): bool {
        session_start();

        // Verificar si la sesión existe
        if (!isset($_SESSION['user_id'])) {
            return false;
        }

        // Verificar timeout de sesión
        $sessionTimeout = $this->config->get('security.session_timeout', 3600);
        $lastActivity = $_SESSION['last_activity'] ?? 0;

        if (time() - $lastActivity > $sessionTimeout) {
            session_destroy();
            return false;
        }

        // Actualizar última actividad
        $_SESSION['last_activity'] = time();

        return true;
    }
}

// Uso
$middleware = new SecurityMiddleware($secureConfig, $auditor, $csrf);
$middleware->run();
```

## 7. Ejemplo de Implementación Completa

```php
<?php
// secure_implementation.php

require 'vendor/autoload.php';

use Tepuilabs\MeliServices\MeliConfig;
use Tepuilabs\MeliServices\MeliServices;

// Inicializar componentes de seguridad
$secureConfig = new SecureConfig();
$auditor = new SecurityAuditor();
$csrf = new CSRFProtection();
$tokenManager = new SecureTokenManager();
$validator = new InputValidator();

// Ejecutar middleware de seguridad
$middleware = new SecurityMiddleware($secureConfig, $auditor, $csrf);
$middleware->run();

// Procesar solicitud
$action = $_GET['action'] ?? '';

try {
    switch ($action) {
        case 'authorize':
            // Validar entrada
            $siteId = $_GET['site'] ?? '';
            if (!$validator->validateSiteId($siteId)) {
                throw new Exception("Site ID inválido");
            }

            // Log de intento de autorización
            $auditor->logAuthorizationAttempt($siteId, true);

            // Generar URL de autorización
            $config = MeliConfig::forAuthorization(
                clientId: $secureConfig->get('client_id'),
                clientSecret: $secureConfig->get('client_secret'),
                redirectUri: $secureConfig->get('redirect_uri'),
                scopes: $secureConfig->get('scopes')
            );

            $meli = new MeliServices($config);
            $authUrl = $meli->getAuthorizationUrl($siteId);

            // Log de acceso a datos
            $auditor->logDataAccess('authorization_url', ['site_id' => $siteId]);

            header('Location: ' . $authUrl);
            exit;

        case 'callback':
            // Validar parámetros del callback
            $code = $_GET['code'] ?? '';
            $state = $_GET['state'] ?? '';

            if (!$validator->validateCode($code)) {
                throw new Exception("Código de autorización inválido");
            }

            if (!$validator->validateState($state)) {
                $auditor->logSuspiciousActivity('Invalid state parameter');
                throw new Exception("State inválido");
            }

            // Intercambiar código por token
            $config = new MeliConfig(
                clientId: $secureConfig->get('client_id'),
                clientSecret: $secureConfig->get('client_secret'),
                code: $code,
                redirectUri: $secureConfig->get('redirect_uri'),
                scopes: $secureConfig->get('scopes')
            );

            $meli = new MeliServices($config);
            $response = $meli->generateAccessToken();

            // Almacenar tokens de forma segura
            $tokenManager->storeTokens([
                'access_token' => $response->getAccessToken(),
                'refresh_token' => $response->getRefreshToken(),
                'expires_in' => $response->getExpiresIn(),
                'user_id' => $response->getUserId()
            ]);

            // Log de operación de token
            $auditor->logTokenOperation('exchange', [
                'user_id' => $response->getUserId(),
                'access_token' => $response->getAccessToken(),
                'expires_in' => $response->getExpiresIn()
            ]);

            echo "✅ Autorización exitosa";
            break;

        default:
            echo "❌ Acción no válida";
    }

} catch (Exception $e) {
    $auditor->logSecurityEvent('error', [
        'action' => $action,
        'error' => $e->getMessage()
    ], 'error');

    echo "❌ Error: " . htmlspecialchars($e->getMessage());
}
```

## Resumen

En este capítulo has aprendido:

- ✅ Almacenamiento seguro de tokens con encriptación
- ✅ Validación robusta de entrada de datos
- ✅ Protección CSRF contra ataques
- ✅ Auditoría completa de seguridad
- ✅ Configuración segura de la aplicación
- ✅ Middleware de seguridad integral
- ✅ Implementación completa y segura
- ✅ Mejores prácticas de producción

## Próximos Pasos

- [09. Casos de Uso Avanzados](./09-casos-uso-avanzados.md)
