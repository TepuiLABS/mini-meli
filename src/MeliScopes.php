<?php

declare(strict_types=1);

namespace Tepuilabs\MeliServices;

/**
 * Scopes and permissions for Mercado Libre API
 */
final readonly class MeliScopes
{
    public const READ = 'read';
    public const WRITE = 'write';
    public const OFFLINE_ACCESS = 'offline_access';

    /**
     * Get all available scopes
     *
     * @return array<string>
     */
    public static function getAll(): array
    {
        return [
            self::READ,
            self::WRITE,
            self::OFFLINE_ACCESS,
        ];
    }

    /**
     * Get default scopes for basic access
     *
     * @return array<string>
     */
    public static function getDefault(): array
    {
        return [
            self::READ,
            self::WRITE,
        ];
    }

    /**
     * Get scopes for offline access (includes refresh token)
     *
     * @return array<string>
     */
    public static function getOfflineAccess(): array
    {
        return [
            self::READ,
            self::WRITE,
            self::OFFLINE_ACCESS,
        ];
    }

    /**
     * Validate if a scope is valid
     */
    public static function isValid(string $scope): bool
    {
        return in_array($scope, self::getAll(), true);
    }

    /**
     * Validate multiple scopes
     *
     * @param array<string> $scopes
     */
    public static function validateScopes(array $scopes): bool
    {
        foreach ($scopes as $scope) {
            if (!self::isValid($scope)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Convert scopes array to string
     *
     * @param array<string> $scopes
     */
    public static function toString(array $scopes): string
    {
        return implode(' ', $scopes);
    }

    /**
     * Convert scopes string to array
     */
    public static function toArray(string $scopes): array
    {
        return array_filter(explode(' ', $scopes));
    }

    /**
     * Check if scopes include offline access
     *
     * @param array<string>|string $scopes
     */
    public static function hasOfflineAccess(array | string $scopes): bool
    {
        $scopesArray = is_array($scopes) ? $scopes : self::toArray($scopes);

        return in_array(self::OFFLINE_ACCESS, $scopesArray, true);
    }

    /**
     * Check if scopes include read permission
     *
     * @param array<string>|string $scopes
     */
    public static function hasRead(array | string $scopes): bool
    {
        $scopesArray = is_array($scopes) ? $scopes : self::toArray($scopes);

        return in_array(self::READ, $scopesArray, true);
    }

    /**
     * Check if scopes include write permission
     *
     * @param array<string>|string $scopes
     */
    public static function hasWrite(array | string $scopes): bool
    {
        $scopesArray = is_array($scopes) ? $scopes : self::toArray($scopes);

        return in_array(self::WRITE, $scopesArray, true);
    }
}
