# Build from the repository root: docker build -f web/Dockerfile .
FROM node:22-bookworm-slim AS dependencies

WORKDIR /workspace
COPY web/package.json web/package-lock.json ./web/
RUN npm ci --prefix web --ignore-scripts --no-audit --no-fund

FROM node:22-bookworm-slim AS build

WORKDIR /workspace
COPY --from=dependencies /workspace/web/node_modules ./web/node_modules
COPY web/package.json web/package-lock.json ./web/
COPY web/src ./web/src
COPY web/tsconfig.json ./web/tsconfig.json
RUN npm run build --prefix web

FROM node:22-bookworm-slim AS runtime

ENV NODE_ENV=production
WORKDIR /app
COPY web/package.json web/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY --from=build /workspace/web/.next ./.next
EXPOSE 3000
USER node
CMD ["npm", "run", "start"]
