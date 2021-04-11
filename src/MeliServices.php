<?php
namespace Tepuilabs\MiniMeLi;

use GuzzleHttp\Client;
use Tepuilabs\MiniMeLi\Exceptions\GenericException;

class MeliServices
{
    protected array $params;

    /**
     * Undocumented function
     *
     * @param array $params
     */
    public function __construct(array $params)
    {
        $this->params = $params;
    }

    /**
     * Undocumented function
     *
     * @return array
     */
    public function generateAccessToken(): array
    {
        $params = [
            'grant_type' => $this->params['grant_type'],
            'client_id' => $this->params['client_id'],
            'code' => $this->params['code'],
            'client_secret' => $this->params['client_secret'],
            'redirect_uri' => $this->params['redirect_uri'],
        ];

        return $this->httpRequest('oauth/token', $params, 'POST');
    }

    /**
     * Undocumented function
     *
     * @param string $url
     * @param array $fields
     * @param string $method
     * @return array
     */
    private function httpRequest(string $url, array $fields, string $method): array
    {
        $client = new Client([
            'base_uri' => 'https://api.mercadolibre.com/',
        ]);

        $args = [];
        if (! in_array($method, ['POST'])) {
            throw new GenericException('Not implemented yet', 1);
        }

        $args['form_params'] = $fields;

        try {
            $request = $client->request($method, $url, $args);
            $body = $request->getBody()->getContents();
            $obj = json_decode($body, true);

            return $obj;
        } catch (GenericException $e) {
            throw new GenericException('Cannot connect to api.mercadolibre.com');
        }
    }
}
