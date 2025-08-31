<?php

require_once __DIR__ . '/../../../vendor/autoload.php';

use controllers\DocumentController;

// Obtener ID del documento de la URL
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$segments = explode('/', trim($uri, '/'));
$documentId = end($segments);

// Llamar al controlador
DocumentController::download($documentId);
