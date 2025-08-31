<?php
namespace config;

use PDO;
use PDOException;

class Database {
    private $host = 'db';   // Cambia esto por tu host si es necesario
    private $db_name = 'my_db_teseract';
    private $username = 'teseract';
    private $password = 'teseract0';
    private $conn;

    public function connect() {
        $this->conn = null;

        try {
            $this->conn = new PDO('mysql:host=' . $this->host . ';dbname=' . $this->db_name, $this->username, $this->password);
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            echo 'Error en la conexión: ' . $e->getMessage();
        }

        return $this->conn;
    }
}
