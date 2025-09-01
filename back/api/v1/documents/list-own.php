<?php

require_once __DIR__ . '/../../../vendor/autoload.php';

use controllers\DocumentController;

// Obtener parámetros de consulta
$input = [
    'page' => $_GET['page'] ?? 1,
    'per_page' => $_GET['per_page'] ?? 10,
    'order' => $_GET['order'] ?? 'desc',
    'search' => $_GET['search'] ?? null
];

// Llamar al controlador
DocumentController::listOwn($input);
