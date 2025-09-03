<?php

namespace controllers;

use config\Database;
use helpers\ApiResponse;

class UserController {
    /**
     * Obtiene la clave pública activa de un usuario por su email
     * @param string $email Email del usuario
     * @return void
     */
    public static function getPublicKey(string $email): void {
        if (empty($email)) {
            ApiResponse::error(
                'Email no proporcionado',
                'Se requiere el parámetro email en la URL (ejemplo: ?email=usuario@dominio.com)',
                400
            );
            return;
        }
        
        try {
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
            
        } catch (\Exception $e) {
            ApiResponse::error(
                'Error al recuperar la clave pública',
                $e->getMessage(),
                500
            );
        }
    }

    /**
     * Lista todos los usuarios activos y confirmados, excluyendo al usuario actual
     * @param string $currentUserEmail Email del usuario que hace la petición
     * @return void
     */
    public static function listActiveUsers(string $currentUserEmail): void {
        try {
            // Conectar a la base de datos
            $db = new Database();
            $conn = $db->connect();
            
            // Obtener usuarios activos y confirmados, excluyendo al usuario actual
            $query = "SELECT id, email 
                     FROM users 
                     WHERE disabled = 0 
                     AND confirmed = 1 
                     AND email != :currentUserEmail
                     ORDER BY email ASC";
                    
            $stmt = $conn->prepare($query);
            $stmt->bindParam(':currentUserEmail', $currentUserEmail);
            $stmt->execute();
            
            $users = $stmt->fetchAll(\PDO::FETCH_ASSOC);
            
            if (empty($users)) {
                ApiResponse::success(
                    ['users' => []],
                    'No se encontraron usuarios activos',
                    200,
                    'users'
                );
                return;
            }
            
            ApiResponse::success(
                ['users' => $users],
                'Usuarios recuperados exitosamente',
                200,
                'users'
            );
            
        } catch (\Exception $e) {
            ApiResponse::error(
                'Error al recuperar la lista de usuarios',
                $e->getMessage(),
                500
            );
        }
    }
}
