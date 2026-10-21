# Build context is the repository root (see docker-compose.yml):
#   docker build -f examples/simple_app/Dockerfile .
FROM composer:2 AS build

WORKDIR /app

COPY composer.json composer.lock ./
RUN composer install --no-interaction --no-progress

FROM php:8.3.36-cli

RUN useradd --create-home --uid 1000 guard

COPY --from=build /app/vendor /app/vendor
COPY src/ /app/src/
COPY examples/simple_app/index.php /app/examples/simple_app/index.php

USER guard
WORKDIR /app

EXPOSE 8080

CMD ["php", "-S", "0.0.0.0:8080", "examples/simple_app/index.php"]
