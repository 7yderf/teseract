<?php

require_once __DIR__ . '/../../../helpers/AuthMiddleware.php';
require_once __DIR__ . '/../../../helpers/ApiResponse.php';
require_once __DIR__ . '/../../../config/database.php';

use helpers\ApiResponse;
use helpers\AuthMiddleware;
use config\Database;

try {
    // Autenticar usuario
    $userData = AuthMiddleware::authenticate();
    
    // Obtener el email del query parameter
    $email = isset($_GET['email']) ? urldecode($_GET['email']) : '';
    
    if (empty($email)) {
        ApiResponse::error(
            'Email no proporcionado',
            'Se requiere el parámetro email en la URL (ejemplo: ?email=usuario@dominio.com)',
            400
        );
        return;
    }
    
    // Conectar a la base de datos
    $db = new Database();
    $conn = $db->connect();
    
    // Buscar la clave pública activa del usuario
    $query = "SELECT uk.public_key 
              FROM users u
              JOIN user_keys uk ON u.id = uk.user_id AND uk.is_active = TRUE
              WHERE u.email = :email 
              AND u.disabled = 0
              LIMIT 1";
              
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    
    $result = $stmt->fetch(\PDO::FETCH_ASSOC);
    
    if (!$result) {
        ApiResponse::error(
            'Usuario no encontrado',
            'No se encontró una clave pública activa para este usuario'. " " . $email,
            404
        );
        return;
    }
    
    ApiResponse::success(
        [
            'email' => $email,
            'public_key' => $result['public_key']
        ],
        'Clave pública recuperada exitosamente',
        200,
        'public_key'
    );
    
} catch (Exception $e) {
    ApiResponse::error(
        'Error al recuperar la clave pública',
        $e->getMessage(),
        500
    );
}
