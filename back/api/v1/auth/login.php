<?php

require_once __DIR__ . '/../../../vendor/autoload.php'; // Cargar el autoload de Composer

use controllers\AuthController;

// Obtener entrada
$input = json_decode(file_get_contents("php://input"), true);

// Llamar al controlador
AuthController::login($input);
