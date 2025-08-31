<?php

namespace helpers;

class ApiResponse
{
    /**
     * Respuesta exitosa bajo JSON:API.
     *
     * @param array|object|null $data Datos principales de la respuesta.
     * @param string|null $message Mensaje para el meta.
     * @param int $statusCode Código HTTP, por defecto 200.
     * @param string|null $type Tipo del recurso.
     */
    public static function success($data, $message = '', $statusCode = 200, $type = null)
    {
        http_response_code($statusCode);

        $response = [
            'data' => $data ? [
                'type' => $type ?? 'resource',
                'id' => $data['id'] ?? null,
                'attributes' => $data
            ] : null,
            'meta' => [
                'message' => $message
            ]
        ];

        echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    }

    /**
     * Respuesta de error bajo JSON:API.
     *
     * @param string $title Título del error.
     * @param string|null $detail Detalle del error.
     * @param int $statusCode Código HTTP, por defecto 400.
     */
    public static function error($title, $detail = null, $statusCode = 400)
    {
        http_response_code($statusCode);

        $response = [
            'errors' => [
                [
                    'status' => (string) $statusCode,
                    'title' => $title,
                    'detail' => $detail
                ]
            ]
        ];

        echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    }
}
