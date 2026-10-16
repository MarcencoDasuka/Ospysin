# syntax=docker/dockerfile:1

# Stage 1: Build Frontend Assets
FROM node:22-alpine AS builder
WORKDIR /app

RUN corepack enable

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .
RUN pnpm build

# Stage 2: Hardened Nginx SPA Web Server
FROM nginxinc/nginx-unprivileged:1.27-alpine AS runtime

USER root
RUN addgroup -g 10001 ospysin && adduser -D -u 10001 -G ospysin ospysin && \
    mkdir -p /var/cache/nginx /var/run /tmp /usr/share/nginx/html /etc/nginx/conf.d && \
    chown -R 10001:10001 /var/cache/nginx /var/run /tmp /usr/share/nginx/html /etc/nginx/conf.d

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html
RUN chown -R 10001:10001 /etc/nginx/conf.d/default.conf /usr/share/nginx/html

USER 10001:10001
EXPOSE 5173

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:5173/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
