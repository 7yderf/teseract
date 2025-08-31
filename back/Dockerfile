# Usa una imagen oficial de PHP con Apache
FROM php:8.2-apache

# Instala la extensión de MySQL
RUN docker-php-ext-install mysqli pdo pdo_mysql

# Copia los archivos de la aplicación al directorio web del contenedor
COPY . /var/www/html/

# Ajusta los permisos de los archivos
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# Habilita módulos de Apache si es necesario
RUN a2enmod rewrite