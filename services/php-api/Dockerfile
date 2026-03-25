FROM php:8.2-cli

WORKDIR /app

COPY public ./public

EXPOSE 8080

CMD ["php", "-S", "0.0.0.0:8080", "-t", "public"]
