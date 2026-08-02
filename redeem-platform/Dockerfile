FROM node:24-bookworm-slim

ENV NODE_ENV=production \
    REDEEM_HOST=0.0.0.0 \
    REDEEM_PORT=8090

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY migrations ./migrations
COPY public ./public
COPY src ./src
COPY test ./test

USER node

EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8090/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]

CMD ["node", "src/server.mjs"]
