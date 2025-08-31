<?php

use helpers\ApiResponse;
use helpers\AuthMiddleware;
use controllers\ProfileController;


$input = json_decode(file_get_contents("php://input"), true);

$currentUser = AuthMiddleware::authenticate(); // Obtener usuario autenticado desde el token
if ($currentUser) {
    ProfileController::showProfile($currentUser);
} else {
    ApiResponse::error(
        'Acceso denegado',
        'Token no válido o expirado.',
        401
    );
}
