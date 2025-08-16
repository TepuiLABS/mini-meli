<?php

declare(strict_types=1);

namespace Tepuilabs\MeliServices;

/**
 * Mercado Libre sites and domains
 */
final readonly class MeliSites
{
    public const MLA = 'MLA'; // Argentina
    public const MLB = 'MLB'; // Brasil
    public const MLM = 'MLM'; // México
    public const MLC = 'MLC'; // Chile
    public const MCO = 'MCO'; // Colombia
    public const MPE = 'MPE'; // Perú
    public const MLU = 'MLU'; // Uruguay
    public const MLV = 'MLV'; // Venezuela

    /**
     * Get all available sites
     *
     * @return array<string, array{name: string, flag: string, domain: string}>
     */
    public static function getAll(): array
    {
        return [
            self::MLA => ['name' => 'Argentina', 'flag' => '🇦🇷', 'domain' => 'ar'],
            self::MLB => ['name' => 'Brasil', 'flag' => '🇧🇷', 'domain' => 'br'],
            self::MLM => ['name' => 'México', 'flag' => '🇲🇽', 'domain' => 'mx'],
            self::MLC => ['name' => 'Chile', 'flag' => '🇨🇱', 'domain' => 'cl'],
            self::MCO => ['name' => 'Colombia', 'flag' => '🇨🇴', 'domain' => 'co'],
            self::MPE => ['name' => 'Perú', 'flag' => '🇵🇪', 'domain' => 'pe'],
            self::MLU => ['name' => 'Uruguay', 'flag' => '🇺🇾', 'domain' => 'uy'],
            self::MLV => ['name' => 'Venezuela', 'flag' => '🇻🇪', 'domain' => 've'],
        ];
    }

    /**
     * Get site information
     */
    public static function getSite(string $siteId): ?array
    {
        $sites = self::getAll();

        return $sites[strtoupper($siteId)] ?? null;
    }

    /**
     * Get site domain
     */
    public static function getDomain(string $siteId): string
    {
        $site = self::getSite($siteId);

        return $site['domain'] ?? 'ar'; // Default to Argentina
    }

    /**
     * Get site name
     */
    public static function getName(string $siteId): string
    {
        $site = self::getSite($siteId);

        return $site['name'] ?? 'Argentina';
    }

    /**
     * Get site flag
     */
    public static function getFlag(string $siteId): string
    {
        $site = self::getSite($siteId);

        return $site['flag'] ?? '🇦🇷';
    }

    /**
     * Check if site is valid
     */
    public static function isValid(string $siteId): bool
    {
        return self::getSite($siteId) !== null;
    }

    /**
     * Get authorization URL for a site
     */
    public static function getAuthorizationUrl(string $siteId): string
    {
        $domain = self::getDomain($siteId);

        return "https://auth.mercadolibre.com.{$domain}/authorization";
    }

    /**
     * Get API base URL
     */
    public static function getApiUrl(): string
    {
        return 'https://api.mercadolibre.com';
    }

    /**
     * Get OAuth token endpoint
     */
    public static function getOAuthTokenEndpoint(): string
    {
        return self::getApiUrl() . '/oauth/token';
    }
}
