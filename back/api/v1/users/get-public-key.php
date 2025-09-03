<?php

use helpers\ApiResponse;
use helpers\AuthMiddleware;
use controllers\UserController;

// Autenticar usuario
$currentUser = AuthMiddleware::authenticate(); // 
if ($currentUser) {
   // Obtener el email del query parameter y pasarlo al controlador
    $email = isset($_GET['email']) ? urldecode($_GET['email']) : '';
    UserController::getPublicKey($email);
} else {
    ApiResponse::error(
        'Acceso denegado',
        'Token no válido o expirado.',
        401
    );
}


