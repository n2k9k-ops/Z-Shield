# Image du frontend. Multi-étapes : les dépendances de build ne partent pas en
# production, et le processus ne tourne pas en root.
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY apps/web/package.json apps/web/
RUN npm ci
# En monorepo, npm regroupe les dépendances à la racine ; ce dossier n'est pas
# toujours créé. On le garantit pour que le COPY de l'étape suivante réussisse.
RUN mkdir -p apps/web/node_modules

FROM node:22-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/apps/web/node_modules ./apps/web/node_modules
COPY package.json ./
COPY apps/web ./apps/web
WORKDIR /app/apps/web
ENV NEXT_TELEMETRY_DISABLED=1
# Next fige les rewrites (proxy /api et /ws) au moment de la CONSTRUCTION.
# L'URL de l'API doit donc être connue ici, pas seulement au démarrage.
# Render fournit la valeur au build car la variable existe sur le service et
# l'ARG porte le même nom.
ARG ZSHIELD_API_ORIGIN
ENV ZSHIELD_API_ORIGIN=$ZSHIELD_API_ORIGIN
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app/apps/web
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
COPY --from=build /app/node_modules /app/node_modules
COPY --from=build /app/apps/web ./
USER node
EXPOSE 3000
# Le frontend n'a aucune dépendance à interroger : il proxifie /api vers l'API,
# qui a son propre health check.
HEALTHCHECK --interval=15s --timeout=3s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/login').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["npx", "next", "start", "-p", "3000"]
