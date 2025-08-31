<?php

namespace helpers;

class Router
{
    private $routes = [];

    public function register($method, $path, $handler)
    {
        $this->routes[] = [
            'method' => strtoupper($method),
            'path' => $path,
            'handler' => $handler
        ];
    }

    public function resolve($method, $uri)
    {
        $method = strtoupper($method);

        // Limpiar URI eliminando query parameters
        $uri = strtok($uri, '?');

        foreach ($this->routes as $route) {
            // Convertir ruta a patrón regex
            $pattern = $this->convertPathToRegex($route['path']);

            if ($route['method'] === $method && preg_match($pattern, $uri, $matches)) {
                // Filtrar solo los nombres de parámetro
                $params = array_filter($matches, 'is_string', ARRAY_FILTER_USE_KEY);

                // Incluir el handler con los parámetros
                $this->requireHandler($route['handler'], $params);
                return;
            }
        }

        // Manejar 404
        http_response_code(404);
        echo json_encode(['error' => 'Ruta no encontrada']);
    }

    private function convertPathToRegex($path)
    {
        // Convertir {id} a named capture group
        $pattern = preg_replace('/\{(\w+)\}/', '(?P<$1>\d+)', $path);
        return '@^' . str_replace('/', '\/', $pattern) . '$@D';
    }

    private function requireHandler($handler, $params = [])
    {
        // Crear variables en un ámbito controlado
        $handlerParams = $params;

        // Incluir el handler con los parámetros disponibles como array
        require_once __DIR__ . '/../api/v1/' . $handler;
    }
}