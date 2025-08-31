<?php

namespace controllers;

use helpers\ApiResponse;
use helpers\AuthMiddleware;
use config\database;
use PDO;
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
                      $input['data']['attributes']['encryption_iv'])) {
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
            $encryptionIv = $input['data']['attributes']['encryption_iv'];
            
            // Conectar a la base de datos
            $db = new Database();
            $conn = $db->connect();
            
            // Insertar documento
            $query = "INSERT INTO documents (user_id, name, mime_type, encrypted_content, encryption_iv) 
                     VALUES (:user_id, :name, :mime_type, :encrypted_content, :encryption_iv)";
            
            $stmt = $conn->prepare($query);
            $stmt->bindParam(':user_id', $userId);
            $stmt->bindParam(':name', $name);
            $stmt->bindParam(':mime_type', $mimeType);
            $stmt->bindParam(':encrypted_content', $encryptedContent, PDO::PARAM_LOB);
            $stmt->bindParam(':encryption_iv', $encryptionIv);
            
            if ($stmt->execute()) {
                $documentId = $conn->lastInsertId();
                
                // Registrar evento de subida (opcional para MVP)
                self::logDocumentAccess($conn, $documentId, $userId, 'upload');
                
                ApiResponse::success(
                    ['id' => $documentId, 'name' => $name, 'mime_type' => $mimeType],
                    'Documento subido correctamente',
                    201,
                    'document'
                );
            } else {
                ApiResponse::error(
                    'Error de servidor',
                    'No se pudo guardar el documento',
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
     * Lista los documentos del usuario actual
     * 
     * @return void
     */
    public static function list()
    {
        try {
            // Autenticar usuario
            $userData = AuthMiddleware::authenticate();
            $userId = $userData->userId;
            
            // Conectar a la base de datos
            $db = new Database();
            $conn = $db->connect();
            
            // Consultar documentos propios
            $query = "SELECT d.id, d.name, d.mime_type, d.created_at 
                     FROM documents d 
                     WHERE d.user_id = :user_id 
                     ORDER BY d.created_at DESC";
            
            $stmt = $conn->prepare($query);
            $stmt->bindParam(':user_id', $userId);
            $stmt->execute();
            
            $ownDocuments = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // Consultar documentos compartidos con el usuario
            $queryShared = "SELECT d.id, d.name, d.mime_type, d.created_at, u.email as shared_by 
                           FROM documents d 
                           JOIN document_shares ds ON d.id = ds.document_id 
                           JOIN users u ON ds.shared_by_user_id = u.id
                           WHERE ds.shared_with_user_id = :user_id 
                           ORDER BY ds.created_at DESC";
            
            $stmtShared = $conn->prepare($queryShared);
            $stmtShared->bindParam(':user_id', $userId);
            $stmtShared->execute();
            
            $sharedDocuments = $stmtShared->fetchAll(PDO::FETCH_ASSOC);
            
            // Preparar respuesta
            $documents = [
                'own' => $ownDocuments,
                'shared' => $sharedDocuments
            ];
            
            ApiResponse::success(
                $documents,
                'Documentos recuperados correctamente',
                200,
                'documents'
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
            $query = "SELECT d.*, ds.encrypted_key 
                     FROM documents d 
                     LEFT JOIN document_shares ds ON d.id = ds.document_id AND ds.shared_with_user_id = :user_id 
                     WHERE d.id = :document_id AND (d.user_id = :user_id OR ds.id IS NOT NULL)
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
            
            // Convertir el contenido binario a base64 para transmitirlo
            $document['encrypted_content'] = base64_encode($document['encrypted_content']);
            
            // Eliminar campos innecesarios
            unset($document['user_id']);
            
            ApiResponse::success(
                $document,
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
                          WHERE document_id = :document_id AND shared_with_user_id = :shared_with_user_id LIMIT 1";
            $stmtCheck = $conn->prepare($queryCheck);
            $stmtCheck->bindParam(':document_id', $documentId);
            $stmtCheck->bindParam(':shared_with_user_id', $sharedWithUserId);
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
                           (document_id, shared_by_user_id, shared_with_user_id, encrypted_key) 
                           VALUES (:document_id, :shared_by_user_id, :shared_with_user_id, :encrypted_key)";
            
            $stmtInsert = $conn->prepare($queryInsert);
            $stmtInsert->bindParam(':document_id', $documentId);
            $stmtInsert->bindParam(':shared_by_user_id', $userId);
            $stmtInsert->bindParam(':shared_with_user_id', $sharedWithUserId);
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
