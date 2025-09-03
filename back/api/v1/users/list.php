<?php
use helpers\ApiResponse;
use helpers\AuthMiddleware;
use controllers\UserController;

// Autenticar usuario
$currentUser = AuthMiddleware::authenticate(); // Obtener usuario autenticado desde el token
if ($currentUser) {
   UserController::listActiveUsers($currentUser->email);
} else {
    ApiResponse::error(
        'Acceso denegado',
        'Token no válido o expirado.',
        401
    );
}


