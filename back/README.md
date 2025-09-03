# 🔥 API Teseract

![PHP](https://img.shields.io/badge/PHP-8.2+-777BB4?logo=php&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-8.0+-4479A1?logo=mysql&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-Autenticación-FF6F00?logo=jsonwebtokens)

API RESTful para el sistema Teseract con gestión de documentos, autenticación JWT y administración de usuarios.

## 🚀 Instalación Rápida

```bash
# 1. Clonar repositorio
git clone https://github.com/7yderf/teseract.git
cd teseract/back

# 2. Instalar dependencias
composer install

# 3. Configurar entorno
cp .env.example .env

# 4. Construir y ejecutar con Docker
docker-compose up -d
```

## ⚙ Configuración Esencial (.env)
```env
# Configuración de Base de Datos
DB_HOST=localhost
DB_NAME=teseract_db
DB_USER=your_user
DB_PASS=your_password

# Configuración JWT
JWT_SECRET_KEY=your_jwt_secret_key
JWT_EXPIRATION=3600

# Configuración de Correo
SMTP_HOST=smtp.gmail.com
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
SMTP_PORT=587
SMTP_SECURE=tls
```

## 🗂 Estructura del Proyecto
```
back/
├── api/
│   └── v1/                 # Endpoints de la API
│       ├── admin/          # Endpoints de administración
│       ├── auth/           # Endpoints de autenticación
│       ├── documents/      # Endpoints de documentos
│       ├── profile/        # Endpoints de perfil
│       └── users/          # Endpoints de usuarios
├── config/                 # Configuraciones
│   ├── database.php       # Configuración de base de datos
│   ├── jwt.php           # Configuración de JWT
│   └── mail.php          # Configuración de correo
├── controllers/           # Controladores de la aplicación
├── helpers/              # Clases auxiliares y utilidades
├── vendor/               # Dependencias de Composer
├── composer.json         # Configuración de dependencias
└── Dockerfile           # Configuración del contenedor
```

## 🔑 Endpoints Principales

### Autenticación 🔐
| Método | Ruta                      | Función                    |
|--------|---------------------------|---------------------------|
| POST   | `/auth/login`             | Iniciar sesión            |
| POST   | `/auth/register`          | Registrar usuario         |
| POST   | `/auth/confirmEmail`      | Confirmar email           |
| POST   | `/auth/forgotPassword`    | Recuperar contraseña      |
| POST   | `/auth/logout`            | Cerrar sesión            |

### Usuarios y Perfiles 👤
| Método | Ruta                      | Función                    |
|--------|---------------------------|---------------------------|
| GET    | `/users`                  | Listar usuarios           |
| GET    | `/users/{id}`             | Obtener usuario           |
| GET    | `/profile`                | Obtener perfil            |
| PUT    | `/profile`                | Actualizar perfil         |

### Documentos 📄
| Método | Ruta                      | Función                    |
|--------|---------------------------|---------------------------|
| GET    | `/documents`              | Listar documentos         |
| POST   | `/documents`              | Crear documento           |
| GET    | `/documents/{id}`         | Obtener documento         |
| PUT    | `/documents/{id}`         | Actualizar documento      |
| DELETE | `/documents/{id}`         | Eliminar documento        |

### Administración ⚙️
| Método | Ruta                      | Función                    |
|--------|---------------------------|---------------------------|
| PUT    | `/admin/disableUser/{id}` | Deshabilitar usuario      |
| GET    | `/admin/users`            | Listar todos los usuarios |

## 🛠 Comandos Útiles

### Pruebas de API
```bash
# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"yourpassword"}'

# Listar documentos (con token JWT)
curl http://localhost:8080/api/v1/documents \
  -H "Authorization: Bearer your_jwt_token"

# Verificar estado del servidor
curl http://localhost:8080/info.php
```

## 📦 Dependencias Principales

- **firebase/php-jwt**: Manejo de tokens JWT
- **phpmailer/phpmailer**: Envío de correos electrónicos
- **guzzlehttp/guzzle**: Cliente HTTP para peticiones

## 🗃 Base de Datos

### Configuración de la Base de Datos

La base de datos se configura automáticamente al levantar el contenedor Docker. El proceso incluye:

1. La estructura de la base de datos se inicializa automáticamente cuando el contenedor de MySQL arranca
2. Los scripts de inicialización están incluidos en la imagen Docker
3. No es necesario ejecutar scripts manualmente, Docker Compose se encarga de todo

> **Nota**: Si necesitas los scripts de la base de datos para desarrollo local, estos se encuentran en:
> - `dump_clean.sql`: Estructura completa de la base de datos


#### Sistema de Usuarios y Permisos

##### Tabla de Módulos
```sql
CREATE TABLE modules (
    id INT NOT NULL AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    PRIMARY KEY (id)
);
```

##### Tabla de Permisos
```sql
CREATE TABLE permissions (
    id INT NOT NULL AUTO_INCREMENT,
    module_id INT NOT NULL,
    actions VARCHAR(255) NOT NULL,
    description VARCHAR(255),
    PRIMARY KEY (id),
    FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE
);
```

##### Tabla de Roles
```sql
CREATE TABLE roles (
    id INT NOT NULL AUTO_INCREMENT,
    role VARCHAR(255) NOT NULL UNIQUE,
    permissions JSON NOT NULL,
    description VARCHAR(255),
    parent_role_id INT,
    PRIMARY KEY (id),
    FOREIGN KEY (parent_role_id) REFERENCES roles(id) ON DELETE SET NULL
);
```

##### Tabla de Usuarios
```sql
CREATE TABLE users (
    id INT NOT NULL AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    confirmed TINYINT(1) NOT NULL DEFAULT '0',
    confirmation_code VARCHAR(255),
    name VARCHAR(100),
    role INT,
    permissions JSON,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    token_version INT DEFAULT '1',
    disabled TINYINT DEFAULT '0',
    PRIMARY KEY (id),
    FOREIGN KEY (role) REFERENCES roles(id) ON DELETE SET NULL
);
```

#### Sistema de Documentos y Encriptación

##### Tabla de Documentos
```sql
CREATE TABLE documents (
    id INT NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    encrypted_content LONGBLOB NOT NULL,
    encryption_iv TEXT NOT NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

##### Tabla de Claves de Documento
```sql
CREATE TABLE document_keys (
    id INT NOT NULL AUTO_INCREMENT,
    document_id INT NOT NULL,
    user_id INT NOT NULL,
    encrypted_key LONGBLOB NOT NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
);
```

##### Tabla de Compartición de Documentos
```sql
CREATE TABLE document_shares (
    id INT NOT NULL AUTO_INCREMENT,
    document_id INT NOT NULL,
    shared_by INT NOT NULL,
    shared_with INT NOT NULL,
    encrypted_key MEDIUMTEXT NOT NULL,
    permissions JSON NOT NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
);
```

##### Tabla de Registro de Accesos a Documentos
```sql
CREATE TABLE document_access_logs (
    id INT NOT NULL AUTO_INCREMENT,
    document_id INT NOT NULL,
    user_id INT NOT NULL,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
);
```

##### Tabla de Claves de Usuario
```sql
CREATE TABLE user_keys (
    id INT NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    public_key TEXT NOT NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    is_active TINYINT(1) DEFAULT '1',
    PRIMARY KEY (id)
);
```
```

## 🛡️ Seguridad
- Autenticación JWT con expiración
- Encriptación AES-256 para datos sensibles
- Validación de permisos por roles
- Protección contra inyecciones SQL

## 📄 Licencia
MIT License - Ver [LICENSE](LICENSE) para detalles completos.

---

Desarrollado con ❤️ por [Fredy Nazario](https://github.com/7yderf)  
