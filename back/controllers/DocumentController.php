<?php

namespace controllers;

use helpers\ApiResponse;
use helpers\AuthMiddleware;
use config\database;
use PDO;
use PDOException;
use Exception;

class DocumentController
{
    /**
     * Sube un documento cifrado al servidor
     * 
     * @param array $input Datos de entrada con el documento cifrado
     * @return void
     */
    public static function upload($input)
    {
        try {
            // Autenticar usuario
            $userData = AuthMiddleware::authenticate();
            $userId = $userData->userId;
            
            // Validar entrada
            if (!isset($input['data']['attributes']['name'], 
                      $input['data']['attributes']['mime_type'],
                      $input['data']['attributes']['encrypted_content'],
                      $input['data']['attributes']['encryption_iv'],
                      $input['data']['attributes']['encrypted_key'])) {
                ApiResponse::error(
                    'Datos incompletos',
                    'Faltan campos requeridos para el documento',
                    400
                );
                return;
            }
            
            $name = $input['data']['attributes']['name'];
            $mimeType = $input['data']['attributes']['mime_type'];
            $encryptedContent = base64_decode($input['data']['attributes']['encrypted_content']);
            $encryptionIv = base64_decode($input['data']['attributes']['encryption_iv']);
            $encryptedKey = $input['data']['attributes']['encrypted_key'];
            
            // Conectar a la base de datos
            $db = new Database();
            $conn = $db->connect();
            
            // Iniciar transacción
            $conn->beginTransaction();
            
            try {
                // Insertar documento
                $query = "INSERT INTO documents (user_id, name, mime_type, encrypted_content, encryption_iv) 
                         VALUES (:user_id, :name, :mime_type, :encrypted_content, :encryption_iv)";
                
                $stmt = $conn->prepare($query);
                $stmt->bindParam(':user_id', $userId);
                $stmt->bindParam(':name', $name);
                $stmt->bindParam(':mime_type', $mimeType);
                $stmt->bindParam(':encrypted_content', $encryptedContent, PDO::PARAM_LOB);
                $stmt->bindParam(':encryption_iv', $encryptionIv);
                $stmt->execute();
                
                $documentId = $conn->lastInsertId();
                
                // Insertar clave del documento
                $queryKey = "INSERT INTO document_keys (document_id, user_id, encrypted_key) 
                            VALUES (:document_id, :user_id, :encrypted_key)";
                            
                $stmtKey = $conn->prepare($queryKey);
                $stmtKey->bindParam(':document_id', $documentId);
                $stmtKey->bindParam(':user_id', $userId);
                $stmtKey->bindParam(':encrypted_key', $encryptedKey);
                $stmtKey->execute();
                
                // Registrar evento de subida (opcional para MVP)
                self::logDocumentAccess($conn, $documentId, $userId, 'upload');
                
                // Confirmar transacción
                $conn->commit();
                
                ApiResponse::success(
                    ['id' => $documentId, 'name' => $name, 'mime_type' => $mimeType],
                    'Documento subido correctamente',
                    201,
                    'document'
                );
            } catch (Exception $e) {
                // Revertir transacción en caso de error
                $conn->rollBack();
                throw $e;
            }
            
            
        } catch (Exception $e) {
            ApiResponse::error(
                'Error de autenticación',
                $e->getMessage(),
                401
            );
        }
    }

    /**
     * Lista los documentos propios del usuario con paginación y filtros
     * 
     * @param array $input Parámetros de entrada para paginación y filtrado
     * @return void
     */
    public static function listOwn($input)
    {
        try {
            // Autenticar usuario
            $userData = AuthMiddleware::authenticate();
            $userId = $userData->userId;
            
            // Validar y sanitizar la entrada
            if (!is_array($input)) {
                $input = [];
            }
            
            // Parámetros de paginación y filtrado con validación
            $page = isset($input['page']) && is_numeric($input['page']) ? max(1, (int)$input['page']) : 1;
            $perPage = isset($input['per_page']) && is_numeric($input['per_page']) ? min(50, max(1, (int)$input['per_page'])) : 10;
            $order = isset($input['order']) && in_array(strtolower($input['order']), ['asc', 'desc']) ? 
                     strtoupper($input['order']) : 'DESC';
            $search = isset($input['search']) && is_string($input['search']) ? trim($input['search']) : null;
            
            // Conectar a la base de datos
            $db = new Database();
            $conn = $db->connect();
            
            // Construir consulta base con mejor manejo de errores
            try {
                $baseQuery = "SELECT d.id, d.name, d.mime_type, d.created_at,
                             dk.encrypted_key
                             FROM documents d 
                             INNER JOIN document_keys dk ON d.id = dk.document_id 
                             WHERE dk.user_id = :user_id AND d.deleted_at IS NULL";
                
                error_log("Usuario ID: " . $userId);
                $params = ['user_id' => $userId];
                
                // Aplicar filtros de búsqueda
                if ($search) {
                    $baseQuery .= " AND d.name LIKE :search";
                    $params['search'] = "%$search%";
                }
                
                // Ordenamiento
                $baseQuery .= " ORDER BY d.created_at $order";
                
                error_log("Query base: " . $baseQuery);
                error_log("Parámetros: " . print_r($params, true));
                
                // Consulta para el total de registros
                $totalQuery = "SELECT COUNT(*) as total FROM ($baseQuery) as total_query";
                $stmtTotal = $conn->prepare($totalQuery);
                
                foreach ($params as $key => $value) {
                    error_log("Binding parámetro '$key' con valor: " . $value);
                    $stmtTotal->bindValue(":$key", $value);
                }
                
                $stmtTotal->execute();
                $total = $stmtTotal->fetchColumn();
                error_log("Total de registros encontrados: " . $total);
                
            } catch (PDOException $e) {
                error_log("Error en consulta SQL: " . $e->getMessage());
                error_log("SQL State: " . $e->errorInfo[0]);
                error_log("Error Code: " . $e->errorInfo[1]);
                error_log("Message: " . $e->errorInfo[2]);
                throw new Exception("Error en la consulta de documentos: " . $e->getMessage());
            }
            
            // Cálculos de paginación
            $lastPage = max(ceil($total / $perPage), 1);
            $currentPage = min($page, $lastPage);
            $offset = ($currentPage - 1) * $perPage;
            
            // Consulta paginada
            $query = $baseQuery . " LIMIT :offset, :limit";
            $stmt = $conn->prepare($query);
            
            // Bind parameters
            foreach ($params as $key => $value) {
                $stmt->bindValue(":$key", $value);
            }
            $stmt->bindValue(':offset', $offset, \PDO::PARAM_INT);
            $stmt->bindValue(':limit', $perPage, \PDO::PARAM_INT);
            $stmt->execute();
            
            $documents = $stmt->fetchAll(\PDO::FETCH_ASSOC);
            
            // Calcular from y to
            $from = $total > 0 ? $offset + 1 : 0;
            $to = min($offset + $perPage, $total);
            if (count($documents) < $perPage) {
                $to = $offset + count($documents);
            }
            
            ApiResponse::success([
                'data' => $documents,
                'pagination' => [
                    'total' => $total,
                    'per_page' => $perPage,
                    'current_page' => $currentPage,
                    'last_page' => $lastPage,
                    'from' => $from,
                    'to' => $to,
                    'prev_page' => $currentPage > 1 ? $currentPage - 1 : null,
                    'next_page' => $currentPage < $lastPage ? $currentPage + 1 : null
                ]
            ], 'Documentos recuperados correctamente', 200, 'documents');
            
        } catch (Exception $e) {
            // Si es un error específico de autenticación
            if (strpos($e->getMessage(), 'Token') !== false || strpos($e->getMessage(), 'autenticación') !== false) {
                ApiResponse::error(
                    'Error de autenticación',
                    $e->getMessage(),
                    401
                );
            } else {
                // Loguear el error para debugging
                error_log("Error en listOwn: " . $e->getMessage());
                error_log("Stack trace: " . $e->getTraceAsString());
                
                // Para otros tipos de errores
                ApiResponse::error(
                    'Error al recuperar documentos',
                    'Detalles del error: ' . $e->getMessage() . 
                    '. Código del error: ' . $e->getCode() . 
                    '. En el archivo: ' . $e->getFile() . 
                    ' línea: ' . $e->getLine(),
                    500
                );
            }
        }
    }

    /**
     * Lista los documentos compartidos con el usuario con paginación y filtros
     */
    public static function listShared($input)
    {
        try {
            // Autenticar usuario
            $userData = AuthMiddleware::authenticate();
            $userId = $userData->userId;
            
            // Parámetros de paginación y filtrado
            $page = max(1, $input['page'] ?? 1);
            $perPage = min(50, $input['per_page'] ?? 10);
            $order = in_array(strtolower($input['order'] ?? 'desc'), ['asc', 'desc']) ? strtoupper($input['order']) : 'DESC';
            $search = $input['search'] ?? null;
            
            // Conectar a la base de datos
            $db = new Database();
            $conn = $db->connect();
            
            // Construir consulta base
            $baseQuery = "SELECT d.id, d.name, d.mime_type, d.created_at, 
                         u.email as shared_by, ds.created_at as shared_at,
                         dk.encrypted_key
                         FROM documents d 
                         JOIN document_shares ds ON d.id = ds.document_id 
                         JOIN users u ON ds.shared_by = u.id
                         LEFT JOIN document_keys dk ON d.id = dk.document_id AND dk.user_id = :user_id
                         WHERE ds.shared_with = :user_id 
                         AND d.deleted_at IS NULL 
                         AND ds.deleted_at IS NULL";
            
            $params = ['user_id' => $userId];
            
            // Aplicar filtros de búsqueda
            if ($search) {
                $baseQuery .= " AND (d.name LIKE :search OR u.email LIKE :search)";
                $params['search'] = "%$search%";
            }
            
            // Ordenamiento
            $baseQuery .= " ORDER BY ds.created_at $order";
            
            // Consulta para el total de registros
            $totalQuery = "SELECT COUNT(*) as total FROM ($baseQuery) as total_query";
            $stmtTotal = $conn->prepare($totalQuery);
            foreach ($params as $key => $value) {
                $stmtTotal->bindValue(":$key", $value);
            }
            $stmtTotal->execute();
            $total = $stmtTotal->fetchColumn();
            
            // Cálculos de paginación
            $lastPage = max(ceil($total / $perPage), 1);
            $currentPage = min($page, $lastPage);
            $offset = ($currentPage - 1) * $perPage;
            
            // Consulta paginada
            $query = $baseQuery . " LIMIT :offset, :limit";
            $stmt = $conn->prepare($query);
            
            // Bind parameters
            foreach ($params as $key => $value) {
                $stmt->bindValue(":$key", $value);
            }
            $stmt->bindValue(':offset', $offset, \PDO::PARAM_INT);
            $stmt->bindValue(':limit', $perPage, \PDO::PARAM_INT);
            $stmt->execute();
            
            $documents = $stmt->fetchAll(\PDO::FETCH_ASSOC);
            
            // Calcular from y to
            $from = $total > 0 ? $offset + 1 : 0;
            $to = min($offset + $perPage, $total);
            if (count($documents) < $perPage) {
                $to = $offset + count($documents);
            }
            
            ApiResponse::success([
                'data' => $documents,
                'pagination' => [
                    'total' => $total,
                    'per_page' => $perPage,
                    'current_page' => $currentPage,
                    'last_page' => $lastPage,
                    'from' => $from,
                    'to' => $to,
                    'prev_page' => $currentPage > 1 ? $currentPage - 1 : null,
                    'next_page' => $currentPage < $lastPage ? $currentPage + 1 : null
                ]
            ], 'Documentos compartidos recuperados correctamente', 200, 'shared_documents');
            
        } catch (Exception $e) {
            ApiResponse::error(
                'Error al recuperar documentos compartidos',
                $e->getMessage(),
                401
            );
        }
    }
    
    /**
     * Descarga un documento cifrado
     * 
     * @param int $documentId ID del documento a descargar
     * @return void
     */
    public static function download($documentId)
    {
        try {
            // Autenticar usuario
            $userData = AuthMiddleware::authenticate();
            $userId = $userData->userId;
            
            // Validar ID del documento
            if (!$documentId) {
                ApiResponse::error(
                    'ID no válido',
                    'Se debe proporcionar un ID de documento válido',
                    400
                );
                return;
            }
            
            // Conectar a la base de datos
            $db = new Database();
            $conn = $db->connect();
            
            // Verificar acceso al documento (propio o compartido)
            $query = "SELECT d.*, 
                     COALESCE(ds.encrypted_key, dk.encrypted_key) as encrypted_key
                     FROM documents d 
                     LEFT JOIN document_shares ds ON d.id = ds.document_id AND ds.shared_with = :user_id
                     LEFT JOIN document_keys dk ON d.id = dk.document_id AND dk.user_id = :user_id
                     WHERE d.id = :document_id 
                     AND (
                         EXISTS (SELECT 1 FROM document_keys WHERE document_id = d.id AND user_id = :user_id)
                         OR 
                         EXISTS (SELECT 1 FROM document_shares WHERE document_id = d.id AND shared_with = :user_id)
                     )
                     AND d.deleted_at IS NULL
                     LIMIT 1";
            
            $stmt = $conn->prepare($query);
            $stmt->bindParam(':document_id', $documentId);
            $stmt->bindParam(':user_id', $userId);
            $stmt->execute();
            
            $document = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$document) {
                ApiResponse::error(
                    'Documento no encontrado',
                    'El documento solicitado no existe o no tiene permisos para acceder',
                    404
                );
                return;
            }
            
            // Registrar acceso (opcional para MVP)
            self::logDocumentAccess($conn, $documentId, $userId, 'download');
            
            // Preparar respuesta
            $response = [
                'id' => $document['id'],
                'name' => $document['name'],
                'mime_type' => $document['mime_type'],
                'encrypted_content' => base64_encode($document['encrypted_content']),
                'encryption_iv' => base64_encode($document['encryption_iv']),
                'encrypted_key' => $document['encrypted_key'],
                'created_at' => $document['created_at']
            ];
            
            ApiResponse::success(
                $response,
                'Documento recuperado correctamente',
                200,
                'document'
            );
            
        } catch (Exception $e) {
            ApiResponse::error(
                'Error de autenticación',
                $e->getMessage(),
                401
            );
        }
    }
    
    /**
     * Comparte un documento con otro usuario
     * 
     * @param array $input Datos de entrada con la información de compartir
     * @return void
     */
    public static function share($input)
    {
        try {
            // Autenticar usuario
            $userData = AuthMiddleware::authenticate();
            $userId = $userData->userId;
            
            // Validar entrada
            if (!isset($input['data']['attributes']['document_id'], 
                      $input['data']['attributes']['shared_with_email'],
                      $input['data']['attributes']['encrypted_key'])) {
                ApiResponse::error(
                    'Datos incompletos',
                    'Faltan campos requeridos para compartir el documento',
                    400
                );
                return;
            }
            
            $documentId = $input['data']['attributes']['document_id'];
            $sharedWithEmail = $input['data']['attributes']['shared_with_email'];
            $encryptedKey = $input['data']['attributes']['encrypted_key'];
            
            // Conectar a la base de datos
            $db = new Database();
            $conn = $db->connect();
            
            // Verificar propiedad del documento
            $query = "SELECT id FROM documents WHERE id = :document_id AND user_id = :user_id LIMIT 1";
            $stmt = $conn->prepare($query);
            $stmt->bindParam(':document_id', $documentId);
            $stmt->bindParam(':user_id', $userId);
            $stmt->execute();
            
            if (!$stmt->fetch()) {
                ApiResponse::error(
                    'Acceso denegado',
                    'Solo el propietario puede compartir este documento',
                    403
                );
                return;
            }
            
            // Buscar al usuario con quien compartir
            $queryUser = "SELECT id FROM users WHERE email = :email LIMIT 1";
            $stmtUser = $conn->prepare($queryUser);
            $stmtUser->bindParam(':email', $sharedWithEmail);
            $stmtUser->execute();
            
            $sharedWithUser = $stmtUser->fetch(PDO::FETCH_ASSOC);
            
            if (!$sharedWithUser) {
                ApiResponse::error(
                    'Usuario no encontrado',
                    'El correo electrónico proporcionado no corresponde a ningún usuario registrado',
                    404
                );
                return;
            }
            
            $sharedWithUserId = $sharedWithUser['id'];
            
            // Verificar que no se comparta consigo mismo
            if ($sharedWithUserId == $userId) {
                ApiResponse::error(
                    'Operación inválida',
                    'No puedes compartir un documento contigo mismo',
                    400
                );
                return;
            }
            
            // Verificar si ya está compartido con este usuario
            $queryCheck = "SELECT id FROM document_shares 
                          WHERE document_id = :document_id 
                          AND shared_with = :shared_with 
                          AND deleted_at IS NULL LIMIT 1";
            $stmtCheck = $conn->prepare($queryCheck);
            $stmtCheck->bindParam(':document_id', $documentId);
            $stmtCheck->bindParam(':shared_with', $sharedWithUserId);
            $stmtCheck->execute();
            
            if ($stmtCheck->fetch()) {
                ApiResponse::error(
                    'Ya compartido',
                    'El documento ya está compartido con este usuario',
                    409
                );
                return;
            }
            
            // Insertar el registro de compartir
            $queryInsert = "INSERT INTO document_shares 
                           (document_id, shared_by, shared_with, encrypted_key) 
                           VALUES (:document_id, :shared_by, :shared_with, :encrypted_key)";
            
            $stmtInsert = $conn->prepare($queryInsert);
            $stmtInsert->bindParam(':document_id', $documentId);
            $stmtInsert->bindParam(':shared_by', $userId);
            $stmtInsert->bindParam(':shared_with', $sharedWithUserId);
            $stmtInsert->bindParam(':encrypted_key', $encryptedKey);
            
            if ($stmtInsert->execute()) {
                // Registrar evento de compartir (opcional para MVP)
                self::logDocumentAccess($conn, $documentId, $userId, 'share');
                
                ApiResponse::success(
                    ['document_id' => $documentId, 'shared_with' => $sharedWithEmail],
                    'Documento compartido correctamente',
                    200,
                    'share'
                );
            } else {
                ApiResponse::error(
                    'Error de servidor',
                    'No se pudo compartir el documento',
                    500
                );
            }
            
        } catch (Exception $e) {
            ApiResponse::error(
                'Error de autenticación',
                $e->getMessage(),
                401
            );
        }
    }
    
    /**
     * Registra un evento de acceso a un documento (opcional para MVP)
     * 
     * @param PDO $conn Conexión a la base de datos
     * @param int $documentId ID del documento
     * @param int $userId ID del usuario
     * @param string $action Tipo de acción realizada
     * @return void
     */
    private static function logDocumentAccess($conn, $documentId, $userId, $action)
    {
        // Para el MVP esto podría ser opcional
        try {
            $ipAddress = $_SERVER['REMOTE_ADDR'] ?? null;
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
            
            $query = "INSERT INTO document_access_logs 
                     (document_id, user_id, action, ip_address, user_agent) 
                     VALUES (:document_id, :user_id, :action, :ip_address, :user_agent)";
            
            $stmt = $conn->prepare($query);
            $stmt->bindParam(':document_id', $documentId);
            $stmt->bindParam(':user_id', $userId);
            $stmt->bindParam(':action', $action);
            $stmt->bindParam(':ip_address', $ipAddress);
            $stmt->bindParam(':user_agent', $userAgent);
            $stmt->execute();
        } catch (Exception $e) {
            // Simplemente registramos el error pero no detenemos el flujo principal
            error_log('Error al registrar acceso: ' . $e->getMessage());
        }
    }
}
