# Image de l'API. Multi-étapes : les dépendances de développement ne partent
# pas en production, et le processus ne tourne pas en root.
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY apps/api/package.json apps/api/
RUN npm ci --omit=dev
# En monorepo, npm regroupe les dépendances à la racine ; ce dossier n'est pas
# toujours créé. On le garantit pour que le COPY de l'étape suivante réussisse.
RUN mkdir -p apps/api/node_modules

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/apps/api/node_modules ./apps/api/node_modules
COPY package.json ./
COPY apps/api ./apps/api
COPY db ./db

# Utilisateur non privilégié fourni par l'image.
USER node

EXPOSE 4000

# /healthz ne touche ni la base ni Redis : un health check qui dépend de la base
# fait tuer le conteneur quand c'est la base qui est lente.
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "--experimental-strip-types", "apps/api/src/server.ts"]
