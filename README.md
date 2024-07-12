<p align="center">
	<img src="carbon_new.png" width="1028">
</p>


## mini-meli

[![Latest Version on Packagist](https://img.shields.io/packagist/v/tepuilabs/mini-meli.svg?style=flat-square)](https://packagist.org/packages/tepuilabs/mini-meli)
[![Total Downloads](https://img.shields.io/packagist/dt/tepuilabs/mini-meli.svg?style=flat-square)](https://packagist.org/packages/tepuilabs/mini-meli)


Genera access token de mercado libre.


la idea de esto es poder generar access token para poder tener acceso a los recursos de Mercado libre.


### como usar


usando composer

```bash
composer require tepuilabs/mini-meli
```

agrega en tu archivo de configuración lo siguiente:

```yml
GRANT_TYPE=authorization_code
CLIENT_ID=
CLIENT_SECRET=
REDIRECT_URL=http://localhost:9000
```
> [!NOTE]
> estos datos los debes configurar en mercado libre cuando crees una aplicación, los unicos datos que necesitas son el client id / secret


Luego necesitas configurar algo como lo siguiente:

```php
<?php

use Tepuilabs\MiniMeLi\MeliServices;

require 'vendor/autoload.php';

$params = [
    'grant_type' => '', // default authorization_code
    'client_id' => '',
    'code' => $_GET['code'], // from url
    'client_secret' => '',
    'redirect_uri' => ''
];

$response = (new MeliServices($params))->generateAccessToken();
```
