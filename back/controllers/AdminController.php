<?php

namespace controllers;

use config\database; // Importar la clase Database
use helpers\ApiResponse;
use helpers\Encryption; // Importar la clase Encryption

class AdminController
{
    /**
     * Deshabilitar un usuario.
     *
     * @param array $input Entrada en formato JSON:API.
     * @param object $currentUser Usuario autenticado (incluye permisos).
     */
    public static function disableUser($input, $currentUser)
    {
        // Validar que el usuario tenga permisos administrativos
        if (!isset($currentUser->permissions) || !$currentUser->permissions) {
            ApiResponse::error(
                'Acceso denegado',
                'No tienes permisos para realizar esta acción.',
                403
            );
            return;
        }

        // Verificar permisos específicos (ejemplo: módulo "user", acción "inhabilitar")
        $permissions = $currentUser->permissions;
        $decryptedPayload = Encryption::decryptPayload($permissions);
        $permissionsDecode = json_decode($decryptedPayload, true);
        
        $hasPermission = array_filter($permissionsDecode, function ($perm) {
            return $perm["module"] === "user" && $perm["actions"] === "inhabilitar";
        });

        if (empty($hasPermission)) {
            ApiResponse::error(
                'Acceso denegado',
                'No tienes permisos suficientes para realizar esta acción.',
                403
            );
            return;
        }

        // Validar entrada en formato JSON:API
        if (!isset($input['data']['attributes']['userId'])) {
            ApiResponse::error(
                'Formato inválido',
                'El ID de usuario es requerido.',
                400
            );
            return;
        }

        $userId = $input['data']['attributes']['userId'];

        // Conectar a la base de datos
        $db = new Database();
        $conn = $db->connect();

        // Marcar usuario como deshabilitado
        $query = 'UPDATE users SET disabled = 1 WHERE id = :userId';
        $stmt = $conn->prepare($query);
        $stmt->execute(['userId' => $userId]);

        ApiResponse::success(
            ['userId' => $userId],
            'Usuario deshabilitado exitosamente.',
            200,
            'users'
        );
    }
}
