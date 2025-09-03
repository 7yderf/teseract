<?php

use helpers\ApiResponse;
use helpers\AuthMiddleware;
use controllers\DocumentController;

$currentUser = AuthMiddleware::authenticate(); // Obtener usuario autenticado desde el token
if ($currentUser) {
    // Obtener parámetros de consulta
$input = [
    'page' => $_GET['page'] ?? 1,
    'per_page' => $_GET['per_page'] ?? 10,
    'order' => $_GET['order'] ?? 'desc',
    'search' => $_GET['search'] ?? null
];

// Llamar al controlador
DocumentController::listOwn($input);

} else {
    ApiResponse::error(
        'Acceso denegado',
        'Token no válido o expirado.',
        401
    );
}

