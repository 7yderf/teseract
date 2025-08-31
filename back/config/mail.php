<?php

return [
    'host' => getenv('SMTP_HOST') ?: 'smtp.example.com',
    'username' => getenv('SMTP_USER') ?: 'user@example.com',
    'password' => getenv('SMTP_PASS') ?: 'password',
    'port' => getenv('SMTP_PORT') ?: 587,
    'encryption' => getenv('SMTP_ENCRYPTION') ?: 'tls',
    'from_email' => getenv('SMTP_FROM_EMAIL') ?: 'no-reply@example.com',
    'from_name' => getenv('SMTP_FROM_NAME') ?: 'Mi Aplicación'
];