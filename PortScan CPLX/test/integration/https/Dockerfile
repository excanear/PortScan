FROM nginx:alpine
RUN apk add --no-cache openssl
COPY default.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html
RUN mkdir -p /etc/nginx/certs && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -subj "/CN=localhost" \
        -keyout /etc/nginx/certs/tls.key \
        -out /etc/nginx/certs/tls.crt && \
    chmod 644 /etc/nginx/certs/tls.crt && chmod 600 /etc/nginx/certs/tls.key
