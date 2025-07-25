<?php

declare(strict_types=1);

namespace Tepuilabs\MeliServices\Exceptions;

use Exception;
use Throwable;

/**
 * Generic exception for Mercado Libre API errors
 */
final class GenericException extends Exception
{
    public function __construct(
        string $message = '',
        int $code = 0,
        ?Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * Create exception for missing required parameter
     */
    public static function missingParameter(string $parameter): self
    {
        return new self("El parámetro '{$parameter}' es requerido");
    }

    /**
     * Create exception for invalid API response
     */
    public static function invalidApiResponse(string $details = ''): self
    {
        $message = 'Respuesta inválida de la API de Mercado Libre';
        if ($details) {
            $message .= ": {$details}";
        }

        return new self($message);
    }

    /**
     * Create exception for network/connection errors
     */
    public static function networkError(string $details = ''): self
    {
        $message = 'Error de conexión con Mercado Libre';
        if ($details) {
            $message .= ": {$details}";
        }

        return new self($message);
    }
}
