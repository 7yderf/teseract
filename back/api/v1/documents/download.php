<?php

use helpers\ApiResponse;
use helpers\AuthMiddleware;
use controllers\DocumentController;

$currentUser = AuthMiddleware::authenticate(); // Obtener usuario autenticado desde el token


if ($currentUser) {
  // Obtener ID del documento de la URL
  $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
  $segments = explode('/', trim($uri, '/'));
  $documentId = end($segments);

  // Llamar al controlador
  DocumentController::download($documentId);
  } else {
    ApiResponse::error(
        'Acceso denegado',
        'Token no válido o expirado.',
        401
    );
}