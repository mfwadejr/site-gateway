FROM node:22-alpine

WORKDIR /app
RUN apk add --no-cache su-exec && corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --prod --frozen-lockfile
COPY src ./src
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh && mkdir -p /data

ENV NODE_ENV=production \
    ADMIN_PORT=8080 \
    DATA_DIR=/data \
    PUID=1000 \
    PGID=1000

VOLUME ["/data"]
EXPOSE 8080 9000-9099
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["node", "src/server.js"]
