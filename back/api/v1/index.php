<?php

require_once __DIR__ . '/../../vendor/autoload.php'; // Cargar el autoload de Composer

use helpers\Router;

// Inicializar el enrutador
global $router;
$router = new Router();

// Registrar rutas de autenticación
$router->register('POST', '/api/v1/auth/login', 'auth/login.php');
$router->register('POST', '/api/v1/auth/register', 'auth/register.php');
$router->register('POST', '/api/v1/auth/confirm-email', 'auth/confirmEmail.php');
$router->register('POST', '/api/v1/auth/logout', 'auth/logout.php');
$router->register('POST', '/api/v1/auth/forgot-password', 'auth/forgotPassword.php');

// Registrar rutas comunes
$router->register('POST', '/api/v1/common/reset-password', 'common/resetPassword.php');

// Registrar rutas administrativas
$router->register('POST', '/api/v1/admin/disable-user', 'admin/disableUser.php');

// Resolver rutas protegidas
$router->register('GET', '/api/v1/profile/show', 'profile/showProfile.php');

// Registrar rutas para documentos
$router->register('POST', '/api/v1/documents/upload', 'documents/upload.php');
$router->register('GET', '/api/v1/documents/list', 'documents/list.php');
$router->register('GET', '/api/v1/documents/download/{id}', 'documents/download.php');
$router->register('POST', '/api/v1/documents/share', 'documents/share.php');

// Resolver la solicitud actual
$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$router->resolve($method, $uri);
