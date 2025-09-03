<?php
use helpers\ApiResponse;
use helpers\AuthMiddleware;
use controllers\DocumentController;


$currentUser = AuthMiddleware::authenticate(); // Obtener usuario autenticado desde el token
if ($currentUser) {
    // Obtener entrada
    $input = json_decode(file_get_contents("php://input"), true);
    // Llamar al controlador
    DocumentController::upload($input);
} else {
    ApiResponse::error(
        'Acceso denegado',
        'Token no válido o expirado.',
        401
    );
}
