<?php

namespace controllers;

use config\database; // Importar la clase Database
use helpers\ApiResponse;
use helpers\Encryption; // Importar la clase Encryption

class ProfileController
{
    /**
     * Deshabilitar un usuario.
     *
     * @param array $input Entrada en formato JSON:API.
     * @param object $currentUser Usuario autenticado (incluye permisos).
     */
    public static function showProfile( $currentUser)
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
        
        ApiResponse::success(
            [
                'user' => $currentUser,
                'permissions' => $permissionsDecode
            ],
            'Usuario deshabilitado exitosamente.',
            200,
            'users'
        );
    }
}
