# Используем базовый образ PHP 8.3 FPM
FROM php:8.3-fpm

# Устанавливаем Composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Устанавливаем Symfony CLI
RUN curl -sS https://get.symfony.com/cli/installer | bash

# Копируем файлы приложения в контейнер
COPY . /app

# Переходим в рабочую директорию приложения
WORKDIR /app

# Устанавливаем права доступа на директории
RUN mkdir -p /var/www/html/var/cache/dev /var/www/html/var/log
RUN chown -R www-data:www-data /var/www/html/var/cache /var/www/html/var/log