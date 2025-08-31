<?php

require_once __DIR__ . '/../../../helpers/ApiResponse.php';
require_once __DIR__ . '/../../../controllers/AuthController.php';

use controllers\AuthController;

$input = json_decode(file_get_contents("php://input"), true);

AuthController::forgotPassword($input);
