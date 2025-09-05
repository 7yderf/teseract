<?php

namespace controllers;

use helpers\ApiResponse;
use helpers\EmailHelper;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use config\database; // Importar la clase Database
use helpers\Encryption; // Importar la clase Encryption

class AuthController
{
    public static function login($input)
    {
        if (!isset($input['data']['attributes']['email'], $input['data']['attributes']['password'])) {
            ApiResponse::error(
                'Faltan campos requeridos',
                'El correo y la contraseña son obligatorios.',
                400
            );
            return;
        }

        $email = $input['data']['attributes']['email'];
        $password = $input['data']['attributes']['password'];

        $db = new Database();
        $conn = $db->connect();

        $query = 'SELECT u.id, u.email, u.password, u.role, u.permissions, u.confirmed, u.disabled, u.token_version, 
                        k.public_key 
                 FROM users u 
                 LEFT JOIN user_keys k ON u.id = k.user_id AND k.is_active = TRUE 
                 WHERE u.email = :email LIMIT 1';
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':email', $email);

        if ($stmt->execute()) {
            $user = $stmt->fetch(\PDO::FETCH_ASSOC);

            if ($user) {
                // Verificar si la cuenta está confirmada
                if ($user['confirmed'] == 0) {
                    ApiResponse::error(
                        'Cuenta no confirmada',
                        'Debes confirmar tu correo electrónico antes de iniciar sesión.',
                        403
                    );
                    return;
                }

                // Verificar si el usuario está deshabilitado
                if ($user['disabled'] == 1) {
                    ApiResponse::error(
                        'Cuenta deshabilitada',
                        'Tu cuenta ha sido deshabilitada. Contacta al administrador.',
                        403
                    );
                    return;
                }

                // Validar la contraseña
                if (password_verify($password, $user['password'])) {
                    $permissions = [];
                    // Obtener permisos basados en el rol
                    if (!empty($user['role'])) {
                        $roleQuery = 'SELECT permissions FROM roles WHERE id = :roleId';
                        $roleStmt = $conn->prepare($roleQuery);
                        $roleStmt->bindParam(':roleId', $user['role']);
                        $roleStmt->execute();

                        $role = $roleStmt->fetch(\PDO::FETCH_ASSOC);
                        if ($role) {
                            $rolePermissions = json_decode($role['permissions'], true);
                            $permissions = array_merge($permissions, $rolePermissions);
                        }
                    }

                    // Agregar permisos personalizados del usuario
                    if (!empty($user['permissions'])) {
                        $userPermissions = json_decode($user['permissions'], true);
                        $permissions = array_merge($permissions, $userPermissions);
                    }

                    $permissions = array_unique($permissions);

                    // Obtener detalles de los permisos si existen
                    $detailedPermissions = [];
                    if (!empty($permissions)) {
                        $placeholders = implode(',', array_fill(0, count($permissions), '?'));
                        $permQuery = "SELECT p.id, m.name AS module, p.actions 
                                      FROM permissions p 
                                      INNER JOIN modules m ON p.module_id = m.id 
                                      WHERE p.id IN ($placeholders)";
                        $permStmt = $conn->prepare($permQuery);
                        $permStmt->execute($permissions);

                        $detailedPermissions = $permStmt->fetchAll(\PDO::FETCH_ASSOC);
                    }

                    // Encriptar los permisos detallados
                    $encryptedPermissions = Encryption::encryptPayload(json_encode($detailedPermissions));

                    // Generar el token JWT
                    $config = include __DIR__ . '/../config/jwt.php';

                    $payload = [
                        'iss' => $config['issuer'],
                        'aud' => $config['audience'],
                        'iat' => time(),
                        'exp' => time() + $config['expiration'],
                        'userId' => $user['id'],
                        'email' => $user['email'],
                        'token_version' => $user['token_version'],
                        'permissions' => $encryptedPermissions
                    ];

                    $secret_key = getenv('JWT_SECRET_KEY');

                    $jwt = JWT::encode($payload, $config[$secret_key], 'HS256');

                    ApiResponse::success(
                        [
                            'id' => $user['id'],
                            'token' => $jwt,
                            'email' => $user['email'],
                            'permissions' => $encryptedPermissions,
                            'public_key' => $user['public_key']
                        ],
                        'Inicio de sesión exitoso.',
                        200,
                        'auth'
                    );
                } else {
                    ApiResponse::error('Credenciales inválidas', 'El email o la contraseña son incorrectos.', 401);
                }
            } else {
                ApiResponse::error('Credenciales inválidas', 'El email o la contraseña son incorrectos.', 401);
            }
        } else {
            ApiResponse::error('Error en el servidor', 'No se pudo procesar la solicitud.', 500);
        }
    }

    public static function register($input)
    {
        if (!isset($input['data']['type']) || $input['data']['type'] !== 'users') {
            ApiResponse::error(
                'Formato inválido',
                'El tipo de recurso debe ser "users".',
                400
            );
            return;
        }

        $attributes = $input['data']['attributes'] ?? null;

        if (!$attributes || !isset($attributes['email'], $attributes['password'], $attributes['confirm_password'], $attributes['role'], $attributes['confirmation'])) {
            ApiResponse::error(
                'Faltan campos requeridos',
                'El correo, la contraseña, el rol y la confirmación son obligatorios.',
                400
            );
            return;
        }

        $email = $attributes['email'];
        $password = $attributes['password'];
        $confirmPassword = $attributes['confirm_password'];
        $role = $attributes['role'];
        $confirmationRequired = (bool) $attributes['confirmation'];
        $permissions = $attributes['permissions'] ?? null;

        // Validar contraseñas
        if ($password !== $confirmPassword) {
            ApiResponse::error('Las contraseñas no coinciden', null, 400);
            return;
        }

        $db = new Database();
        $conn = $db->connect();

        // Validar si el correo ya está registrado
        $query = 'SELECT id FROM users WHERE email = :email LIMIT 1';
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':email', $email);
        $stmt->execute();

        if ($stmt->fetch()) {
            ApiResponse::error('El correo ya está registrado', null, 409);
            return;
        }

        // Generar código de confirmación
        $randomCode = bin2hex(random_bytes(8)); // Código alfanumérico de 16 caracteres
        $encryptedCode = Encryption::encryptPayload("{$email}|{$randomCode}"); // Encriptar email y código juntos

        // Comenzar transacción
        $conn->beginTransaction();
        
        try {
            // Registrar el usuario
            $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
            $confirmed = $confirmationRequired ? 0 : 1;

            $insertQuery = 'INSERT INTO users (email, password, role, confirmed, permissions, confirmation_code) 
                            VALUES (:email, :password, :role, :confirmed, :permissions, :confirmation_code)';
            $insertStmt = $conn->prepare($insertQuery);
            $insertStmt->execute([
                'email' => $email,
                'password' => $hashedPassword,
                'role' => $role,
                'confirmed' => $confirmed,
                'permissions' => $permissions ? json_encode($permissions) : null,
                'confirmation_code' => $randomCode
            ]);

            $userId = $conn->lastInsertId();

            // Si no requiere confirmación, generamos las claves inmediatamente
            if (!$confirmationRequired) {
                // Generar par de claves RSA
                $config = [
                    "digest_alg" => "sha256",
                    "private_key_bits" => 2048,
                    "private_key_type" => OPENSSL_KEYTYPE_RSA,
                ];
                
                // Crear el par de claves
                $res = openssl_pkey_new($config);
                if (!$res) {
                    throw new \Exception('Error al generar las claves de seguridad');
                }

                // Obtener la clave privada
                openssl_pkey_export($res, $privateKey);

                // Obtener la clave pública
                $publicKeyDetails = openssl_pkey_get_details($res);
                $publicKey = $publicKeyDetails["key"];
                
                // Limpiar la clave pública (remover headers PEM y saltos de línea)
                $cleanPublicKey = preg_replace('/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/', '', $publicKey);

                // Guardar la clave pública limpia
                $insertKeyQuery = 'INSERT INTO user_keys (user_id, public_key, is_active) VALUES (:user_id, :public_key, TRUE)';
                $insertKeyStmt = $conn->prepare($insertKeyQuery);
                $insertKeyStmt->execute([
                    'user_id' => $userId,
                    'public_key' => $cleanPublicKey
                ]);

                // Enviar la clave privada por correo
                $privateKeyEmailBody = "
                    <meta charset=\"UTF-8\">
                    <h1>Tu Clave Privada</h1>
                    <p>Esta es tu clave privada para cifrar documentos. Guárdala en un lugar seguro y no la compartas con nadie:</p>
                    <pre>{$privateKey}</pre>
                    <p><strong>IMPORTANTE:</strong> Esta clave es necesaria para descifrar tus documentos. 
                    No podrás recuperar esta información más tarde, así que asegúrate de guardarla de forma segura.</p>
                ";

                $sendResult = EmailHelper::send($email, 'Tu Clave Privada - Importante', $privateKeyEmailBody);
                if (!$sendResult) {
                    throw new \Exception('Error al enviar la clave privada por correo');
                }
            }
            
            $conn->commit();
        } catch (\Exception $e) {
            $conn->rollBack();
            ApiResponse::error('Error al registrar el usuario: ' . $e->getMessage(), null, 500);
            return;
        }

        // Enviar correo de confirmación si es necesario
        if ($confirmationRequired) {
            $confirmationLink = "http://example.com/api/v1/auth/confirm-email?code={$encryptedCode}";

            $emailBody = "
                <h1>Confirma tu cuenta</h1>
                <p>Gracias por registrarte. Haz clic en el siguiente enlace para confirmar tu cuenta:</p>
                <a href='{$confirmationLink}'>Confirmar cuenta</a>
            ";

            $sendResult = EmailHelper::send($email, 'Confirma tu cuenta', $emailBody);

            if ($sendResult !== true) {
                ApiResponse::error(
                    "Error al enviar el correo de confirmación: {$sendResult}",
                    null,
                    500
                );
                return;
            }
        }

        // Respuesta JSON:API
        ApiResponse::success(
            [
                'id' => $userId,
                'email' => $email,
                'role' => $role,
                'confirmation_required' => $confirmationRequired
            ],
            'Usuario registrado exitosamente.',
            201,
            'users'
        );
    }

    public static function confirmEmail($input)
    {
        if (!isset($input['data']['attributes']['code'])) {
            ApiResponse::error(
                'El código de confirmación es requerido.',
                null,
                400
            );
            return;
        }

        $encryptedCode = $input['data']['attributes']['code'];

        $db = new Database();
        $conn = $db->connect();

        // Desencriptar el código
        $decryptedPayload = Encryption::decryptPayload($encryptedCode);
        var_dump($decryptedPayload);
        if (!$decryptedPayload) {
        \helpers\ApiResponse::error(
        'Código inválido',
        'El código de confirmación no es válido.',
        400
        );
        return;
        }

        // Separar email y código
        list($email, $randomCode) = explode('|', $decryptedPayload);

        // Verificar que el código exista en la base de datos
        $query = 'SELECT id, confirmed FROM users WHERE email = :email AND confirmation_code = :confirmation_code LIMIT 1';
        $stmt = $conn->prepare($query);
        $stmt->execute([
        'email' => $email,
        'confirmation_code' => $randomCode
        ]);

        $user = $stmt->fetch(\PDO::FETCH_ASSOC);

        if (!$user) {
        \helpers\ApiResponse::error(
        'Código no encontrado',
        'El código de confirmación es incorrecto o ya ha sido usado.',
        400
        );
        return;
        }

        // Verificar si ya está confirmado
        if ($user['confirmed'] == 1) {
        \helpers\ApiResponse::error(
        'Cuenta ya confirmada',
        'Esta cuenta ya ha sido confirmada.',
        400
        );
        return;
        }

        // Iniciar transacción
        $conn->beginTransaction();
        
        try {
            // Marcar como confirmada
            $updateQuery = 'UPDATE users SET confirmed = 1, confirmation_code = NULL WHERE id = :id';
            $updateStmt = $conn->prepare($updateQuery);
            $updateStmt->execute(['id' => $user['id']]);

            // Generar par de claves RSA
            $config = [
                "digest_alg" => "sha256",
                "private_key_bits" => 2048,
                "private_key_type" => OPENSSL_KEYTYPE_RSA,
            ];
            
            // Crear el par de claves
            $res = openssl_pkey_new($config);
            if (!$res) {
                throw new \Exception('Error al generar las claves de seguridad');
            }

            // Obtener la clave privada
            openssl_pkey_export($res, $privateKey);

            // Obtener la clave pública
            $publicKeyDetails = openssl_pkey_get_details($res);
            $publicKey = $publicKeyDetails["key"];
            
            // Limpiar la clave pública (remover headers PEM y saltos de línea)
            $cleanPublicKey = preg_replace('/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/', '', $publicKey);

            // Guardar la clave pública limpia
            $insertKeyQuery = 'INSERT INTO user_keys (user_id, public_key, is_active) VALUES (:user_id, :public_key, TRUE)';
            $insertKeyStmt = $conn->prepare($insertKeyQuery);
            $insertKeyStmt->execute([
                'user_id' => $user['id'],
                'public_key' => $cleanPublicKey
            ]);

            // Enviar la clave privada por correo
            $privateKeyEmailBody = "
                <h1>Tu Clave Privada</h1>
                <p>Esta es tu clave privada para cifrar documentos. Guárdala en un lugar seguro y no la compartas con nadie:</p>
                <pre>{$privateKey}</pre>
                <p><strong>IMPORTANTE:</strong> Esta clave es necesaria para descifrar tus documentos. 
                No podrás recuperar esta información más tarde, así que asegúrate de guardarla de forma segura.</p>
            ";

            $sendResult = EmailHelper::send($email, 'Tu Clave Privada - Importante', $privateKeyEmailBody);
            if (!$sendResult) {
                throw new \Exception('Error al enviar la clave privada por correo');
            }

            $conn->commit();
        } catch (\Exception $e) {
            $conn->rollBack();
            \helpers\ApiResponse::error('Error al confirmar la cuenta: ' . $e->getMessage(), null, 500);
            return;
        }

        // Respuesta exitosa
        \helpers\ApiResponse::success(
        [
        'email' => $email,
        'confirmed' => true,
        'id' => $user['id'],
        ],
        'Cuenta confirmada exitosamente.',
        200,
        'confirmation'
        );
    }

    // Método para manejar recuperación de contraseña
    public static function forgotPassword($input)
    {
        if (!isset($input['data']['attributes']['email'])) {
            ApiResponse::error(
                'El correo electrónico es requerido.',
                null,
                400
            );
            return;
        }

        $email = $input['data']['attributes']['email'];

        $db = new Database();
        $conn = $db->connect();

        $query = 'SELECT id FROM users WHERE email = :email LIMIT 1';
        $stmt = $conn->prepare($query);
        $stmt->bindParam(':email', $email);
        $stmt->execute();

        $user = $stmt->fetch(\PDO::FETCH_ASSOC);

        if (!$user) {
            ApiResponse::error('No se encontró una cuenta asociada con este correo.', null, 404);
            return;
        }

         // Generar código de recuperación
    $randomCode = bin2hex(random_bytes(8)); // Genera un código alfanumérico
    $encryptedCode =  Encryption::encryptPayload($email . '|' . $randomCode); // Encripta el correo y el código juntos
        $updateQuery = 'UPDATE users SET confirmation_code = :confirmation_code WHERE id = :id';
        $updateStmt = $conn->prepare($updateQuery);
        $updateStmt->execute([
            'confirmation_code' => $randomCode,
            'id' => $user['id']
        ]);

        $resetLink = "http://example.com/api/v1/common/reset-password?code={$encryptedCode}";

        $emailBody = "
            <h1>Restablece tu contraseña</h1>
            <p>Haz clic en el siguiente enlace para restablecer tu contraseña:</p>
            <a href='{$resetLink}'>Restablecer contraseña</a>
        ";

        $sendResult = EmailHelper::send($email, 'Recuperación de contraseña', $emailBody);

        if ($sendResult === true) {
            ApiResponse::success(
                null,
                'Correo de recuperación enviado exitosamente.',
                200
            );
        } else {
            ApiResponse::error("Error al enviar el correo de recuperación: {$sendResult}", null, 500);
        }
    }

    public static function resetPassword($input)
    {
        if (!isset($input['data']['attributes']['code'], $input['data']['attributes']['new_password'], $input['data']['attributes']['confirm_password'])) {
            ApiResponse::error(
                'El código, la nueva contraseña y su confirmación son requeridos.',
                null,
                400
            );
            return;
        }

        $code = $input['data']['attributes']['code'];
        $newPassword = $input['data']['attributes']['new_password'];
        $confirmPassword = $input['data']['attributes']['confirm_password'];

        if ($newPassword !== $confirmPassword) {
            ApiResponse::error('Las contraseñas no coinciden.', null, 400);
            return;
        }

        // Desencriptar el código
        $decryptedPayload = Encryption::decryptPayload($code);
        if (!$decryptedPayload) {
            \helpers\ApiResponse::error(
                'Código inválido',
                'El código proporcionado no es válido.',
                400
            );
            return;
        }

        // Separar email y código
        list($email, $randomCode) = explode('|', $decryptedPayload);

        $db = new Database();
        $conn = $db->connect();

        // Verificar código y usuario
        $query = 'SELECT id FROM users WHERE email = :email AND confirmation_code = :confirmation_code LIMIT 1';
        $stmt = $conn->prepare($query);
        $stmt->execute([
            'email' => $email,
            'confirmation_code' => $randomCode
        ]);

        $user = $stmt->fetch(\PDO::FETCH_ASSOC);

        if (!$user) {
            ApiResponse::error('Código de restablecimiento inválido.', null, 400);
            return;
        }

        // Actualizar contraseña
        $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);
        $updateQuery = 'UPDATE users SET password = :password, confirmation_code = NULL WHERE id = :id';
        $updateStmt = $conn->prepare($updateQuery);
        $updateStmt->execute([
            'password' => $hashedPassword,
            'id' => $user['id']
        ]);

        ApiResponse::success(
            null,
            'Contraseña restablecida exitosamente.',
            200
        );
    }

    public static function logout()
    {
        $headers = getallheaders();
        if (!isset($headers['Authorization'])) {
            ApiResponse::error('Falta el token de autorización.', null, 400);
            return;
        }

            $authHeader = $headers['Authorization'];
            list(, $jwt) = explode(' ', $authHeader);

            // Generar el token JWT
            $config = include __DIR__ . '/../config/jwt.php';
            $secret_key = getenv('JWT_SECRET_KEY');

            try{
                $decoded = JWT::decode($jwt, new Key($config[$secret_key], 'HS256'));

            $db = new Database();
            $conn = $db->connect();

            $query = 'UPDATE users SET token_version = token_version + 1 WHERE id = :userId';
            $stmt = $conn->prepare($query);
            $stmt->execute(['userId' => $decoded->userId]);

            ApiResponse::success(
                null,
                'Sesión cerrada exitosamente.',
                200
            );
        } catch (\Exception $e) {
            ApiResponse::error('Token inválido', 'El token JWT proporcionado no es válido.', 400);            
        }
        
    }
}
