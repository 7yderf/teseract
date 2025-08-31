<?php

require_once __DIR__ . '/../../../vendor/autoload.php';

use controllers\DocumentController;

// Obtener entrada
$input = json_decode(file_get_contents("php://input"), true);

// Llamar al controlador
DocumentController::upload($input);
