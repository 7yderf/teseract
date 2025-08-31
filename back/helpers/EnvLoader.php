<?php

function loadEnv($filePath) {


    if (!file_exists($filePath)) {
        throw new Exception("El archivo .env no se encontró en: $filePath");
    }

    $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        // Ignorar comentarios
        if (strpos(trim($line), '#') === 0) {
            continue;
        }

        // Dividir las variables de entorno por el signo "="
        list($key, $value) = explode('=', $line, 2);
        $key = trim($key);
        $value = trim($value);

        // Eliminar comillas de los valores si las hay
        $value = trim($value, '"');

        // Establecer en $_ENV
        $_ENV[$key] = $value;
        putenv("$key=$value");
    }
}