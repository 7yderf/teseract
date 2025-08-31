<?php

require_once './helpers/EnvLoader.php';
require_once './helpers/Router.php';

// Cargar variables de entorno
loadEnv(__DIR__ . '/.env');

// Configurar cabeceras globales
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Crear enrutador
$router = new \helpers\Router();

// Rutas versión 1
require_once './api/v1/index.php';

// Resolver la solicitud
$router->resolve($_SERVER['REQUEST_METHOD'], parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
