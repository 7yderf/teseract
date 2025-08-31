<?php
namespace helpers;

class Encryption
{
    public static function encryptPayload(string $value): string
    {
        $cipher = 'AES-256-CBC';
        $secret_key = getenv('ENCRYPTION_SECRET_KEY') ?: 'default_secret_key';
        $secret_iv = getenv('ENCRYPTION_SECRET_IV') ?: 'default_secret_iv';
        $key = hash('sha256', $secret_key);
        $iv = substr(hash('sha256', $secret_iv), 0, 16);
        $output = openssl_encrypt($value, $cipher, $key, 0, $iv);
        return base64_encode($output);
    }

    public static function decryptPayload(string $encryptedValue): string
    {
        $cipher = 'AES-256-CBC';
        $secret_key = getenv('ENCRYPTION_SECRET_KEY') ?: 'default_secret_key';
        $secret_iv = getenv('ENCRYPTION_SECRET_IV') ?: 'default_secret_iv';
        $key = hash('sha256', $secret_key);
        $iv = substr(hash('sha256', $secret_iv), 0, 16);
        return openssl_decrypt(base64_decode($encryptedValue), $cipher, $key, 0, $iv);
    }
}




