<?php

declare(strict_types=1);

namespace Tepuilabs\MeliServices;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Tepuilabs\MeliServices\Exceptions\GenericException;

class MeliServices
{
    public function __construct(protected array $params)
    {
    }

    /**
     * generate access token
     *
     * @throws GenericException|GuzzleException
     */
    public function generateAccessToken(): array
    {
        return $this->httpRequest([
            'grant_type' => $this->params['grant_type'] ?? 'authorization_code',
            'client_id' => $this->params['client_id'],
            'code' => $this->params['code'],
            'client_secret' => $this->params['client_secret'],
            'redirect_uri' => $this->params['redirect_uri'],
        ]);
    }

    /**
     * make a http request to mercado libre api
     *
     * @throws GenericException|GuzzleException
     */
    private function httpRequest(array $fields): array
    {
        $client = new Client([
            'base_uri' => 'https://api.mercadolibre.com/',
        ]);

        $args = [];

        $args['form_params'] = $fields;

        try {
            $request = $client->request('POST', 'oauth/token', $args);
            $body = $request->getBody()->getContents();

            return json_decode($body, true);
        } catch (Exception $e) {
            throw new GenericException($e->getMessage());
        }
    }
}
