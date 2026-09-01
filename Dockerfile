FROM caddy:2.11.4-alpine AS caddy

FROM node:22-alpine

WORKDIR /app
RUN apk add --no-cache libcap-setcap su-exec tini && corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --prod --frozen-lockfile
COPY src ./src
COPY --from=caddy /usr/bin/caddy /usr/bin/caddy
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh && setcap cap_net_bind_service=+ep /usr/bin/caddy && mkdir -p /data

ENV NODE_ENV=production \
    ADMIN_PORT=8080 \
    DATA_DIR=/data \
    PUID=1000 \
    PGID=1000

VOLUME ["/data"]
EXPOSE 80 443 8080 9000-9099
ENTRYPOINT ["tini", "--", "docker-entrypoint.sh"]
CMD ["node", "src/server.js"]
