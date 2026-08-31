FROM node:22-alpine

WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --prod --frozen-lockfile
COPY src ./src

ENV NODE_ENV=production \
    ADMIN_PORT=8080 \
    DATA_DIR=/data

VOLUME ["/data"]
EXPOSE 8080 9000-9099
USER node
CMD ["node", "src/server.js"]
