# node:22-alpine is multi-arch, so this builds unchanged on an x86 or ARM NAS.
FROM node:22-alpine

WORKDIR /app

# Install deps first so a code change does not invalidate the dependency layer.
# --omit=dev drops topojson-client/world-atlas, which are only needed to
# regenerate public/world-110m.json (already committed).
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server ./server
COPY public ./public
COPY scripts ./scripts

# Optional GeoLite2 mmdb mount point. Without it the service falls back to
# ip-api.com, so an empty directory is fine.
RUN mkdir -p /app/data && chown -R node:node /app

USER node

ENV PORT=8474 HOST=0.0.0.0
EXPOSE 8474

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8474)+'/api/health').then(r=>r.json()).then(h=>process.exit(h.feeds.fw.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server/index.js"]
