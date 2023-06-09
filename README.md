<p align="center">
	<img src="carbon_new.png" width="1028">
</p>


## mini-meli

[![Latest Version on Packagist](https://img.shields.io/packagist/v/tepuilabs/mini-meli.svg?style=flat-square)](https://packagist.org/packages/tepuilabs/mini-meli)
[![Tests](https://img.shields.io/github/actions/workflow/status/tepuilabs/mini-meli/run-tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/tepuilabs/mini-meli/actions/workflows/run-tests.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/tepuilabs/mini-meli.svg?style=flat-square)](https://packagist.org/packages/tepuilabs/payment-processors)


genera acces token de mercado libre.


la idea de esto es poder generar access token para poder tener acceso a los recursos de Mercadolibre.


### como usar


usando composer

```bash
composer require tepuilabs/mini-meli
```

agrega en tu archivo de cofiguración lo siguiente:

```yml
GRANT_TYPE=authorization_code
CLIENT_ID=
CLIENT_SECRET=
REDIREC_URL=http://localhost:9000
```
> **Note**
> estos datos los debes configurar en mercado libre cuando crees una applicación, los unicos datos que necesitas son el client id / secret


luego necesitas configurar algo como lo siguiente:

```php
<?php

use Tepuilabs\MiniMeLi\MeliServices;

require 'vendor/autoload.php';

$params = [
    'grant_type' => '',
    'client_id' => '',
    'code' => $_GET['code'], // from url
    'client_secret' => '',
    'redirect_uri' => ''
];

$response = (new MeliServices($params))->generateAccessToken();

```
