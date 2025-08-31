<?php

namespace helpers;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

class EmailHelper
{
    public static function send($to, $subject, $body)
    {
        $mailConfig = include __DIR__ . '/../config/mail.php';

        $mail = new PHPMailer(true);

        try {
            // Configuración del servidor SMTP
            $mail->isSMTP();
            $mail->Host = $mailConfig['host'];
            $mail->SMTPAuth = true;
            $mail->Username = $mailConfig['username'];
            $mail->Password = $mailConfig['password'];
            $mail->SMTPSecure = $mailConfig['encryption'];  // PHPMailer::ENCRYPTION_STARTTLS 
            $mail->Port = $mailConfig['port'];

            // Configuración del remitente
            $mail->setFrom($mailConfig['from_email'], $mailConfig['from_name']);
            $mail->addAddress($to);

            // Contenido del correo
            $mail->isHTML(true);
            $mail->Subject = $subject;
            $mail->Body = $body;

            // Enviar correo
            $mail->send();
            return true;
        } catch (Exception $e) {
            return "Error: {$mail->ErrorInfo}";
        }
    }
}
