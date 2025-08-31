# 🔥 API To do list - PHP

![PHP](https://img.shields.io/badge/PHP-8.2+-777BB4?logo=php&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-8.0+-4479A1?logo=mysql&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-Autenticación-FF6F00?logo=jsonwebtokens)

API RESTful para gestión de tareas con autenticación JWT, roles y permisos.

## 🚀 Instalación Rápida

```bash
# 1. Clonar repositorio
git clone https://github.com/7yderf/back-todo-list
cd back-todo-list

# 2. Instalar dependencias
composer install

# 3. Configurar entorno
cp .env.example .env

# 4. Construir y ejecutar con Docker
docker build -t api-php . && docker run -p 8080:80 api-php
```

## ⚙ Configuración Esencial (.env)
```env
DB_HOST=db
DB_NAME=my_db_angels
DB_USER=angels
DB_PASS=angels
JWT_SECRET_KEY=tu_clave_super_secreta_123!
SMTP_HOST=smtp.gmail.com
SMTP_USER=tucorreo@gmail.com
SMTP_PASS=tucontraseña
```

## 🗂 Estructura del Proyecto
```
api-to-do-list/
├── api/
│   └── v1/              # Endpoints (auth, tasks, activities)
├── config/              # Configuraciones (DB, JWT, Mail)
├── controllers/         # Lógica de negocio
├── helpers/             # Utilidades (Auth, Responses)
├── docker/              # Configuración Docker
├── composer.json        # Dependencias PHP
└── Dockerfile           # Configuración del contenedor
```

## 🔑 Endpoints Clave

### Autenticación 🔐
| Método | Ruta                     | Función                  |
|--------|--------------------------|--------------------------|
| POST   | `/auth/login`            | Login con JWT            |
| POST   | `/auth/register`         | Registrar usuario        |
| POST   | `/auth/forgot-password`  | Recuperar contraseña     |

### Tareas 📝
| Método | Ruta                     | Función                  |
|--------|--------------------------|--------------------------|
| GET    | `/tasks/list`            | Listar con paginación    |
| POST   | `/tasks/create`          | Crear nueva tarea        |
| PUT    | `/tasks/update/{id}`     | Actualizar tarea         |

### Actividades 🏷️
| Método | Ruta                     | Función                  |
|--------|--------------------------|--------------------------|
| GET    | `/activities/list`       | Obtener todas            |
| POST   | `/activities/create`     | Crear nueva actividad    |

## 🛠 Comandos Útiles

```bash
# Ejecutar tests de API
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"data":{"attributes":{"email":"test@example.com","password":"secret"}}'

# Verificar salud del sistema
curl http://localhost:8080/info.php
```

## 🗃 Script de Base de Datos
```sql
-- Tabla de actividades
CREATE TABLE activities (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  color VARCHAR(7) DEFAULT '#2196F3',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de módulos
CREATE TABLE modules (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL
);

-- Tabla de permisos
CREATE TABLE permissions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  module_id INT NOT NULL,
  actions VARCHAR(255) NOT NULL,
  description VARCHAR(255),
  FOREIGN KEY (module_id) REFERENCES modules(id) ON DELETE CASCADE
);

-- Tabla de roles
CREATE TABLE roles (
  id INT AUTO_INCREMENT PRIMARY KEY,
  role VARCHAR(255) NOT NULL UNIQUE,
  permissions JSON NOT NULL,
  description VARCHAR(255),
  parent_role_id INT,
  FOREIGN KEY (parent_role_id) REFERENCES roles(id) ON DELETE SET NULL
);

-- Tabla de tareas
CREATE TABLE tasks (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  category_id INT NOT NULL,
  status ENUM('pendiente', 'finalizada') DEFAULT 'pendiente',
  deleted TINYINT(1) DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (category_id) REFERENCES activities(id)
);

-- Tabla de usuarios
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  confirmed TINYINT(1) DEFAULT 0,
  confirmation_code VARCHAR(255),
  role INT,
  permissions JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  token_version INT DEFAULT 1,
  disabled TINYINT DEFAULT 0,
  FOREIGN KEY (role) REFERENCES roles(id) ON DELETE SET NULL
);
```

## 🛡️ Seguridad
- Autenticación JWT con expiración
- Encriptación AES-256 para datos sensibles
- Validación de permisos por roles
- Protección contra inyecciones SQL

## 📄 Licencia
MIT License - Ver [LICENSE](LICENSE) para detalles completos.

---

Desarrollado con ❤️ por [Fredy Nazario](https://github.com/tu-usuario)  
[![Contacto](https://img.shields.io/badge/📧-Contactar-blue?style=flat)](mailto:tu@email.com)