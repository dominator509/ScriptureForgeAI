# Build from the repository root: docker build -f web/Dockerfile .
FROM node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5 AS dependencies

WORKDIR /workspace
COPY web/package.json web/package-lock.json ./web/
RUN npm ci --prefix web --ignore-scripts --no-audit --no-fund

FROM node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5 AS build

WORKDIR /workspace
COPY --from=dependencies /workspace/web/node_modules ./web/node_modules
COPY web/package.json web/package-lock.json ./web/
COPY web/src ./web/src
COPY web/tsconfig.json ./web/tsconfig.json
ARG NEXT_PUBLIC_API_BASE_URL
ARG NEXT_PUBLIC_WS_BASE_URL
ARG NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT=production
ENV NEXT_PUBLIC_API_BASE_URL=$NEXT_PUBLIC_API_BASE_URL
ENV NEXT_PUBLIC_WS_BASE_URL=$NEXT_PUBLIC_WS_BASE_URL
ENV NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT=$NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT
RUN test -n "$NEXT_PUBLIC_API_BASE_URL" && test -n "$NEXT_PUBLIC_WS_BASE_URL"
RUN npm run build --prefix web

FROM node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5 AS runtime

ENV NODE_ENV=production
WORKDIR /app
COPY web/package.json web/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY --from=build /workspace/web/.next ./.next
EXPOSE 3000
USER node
CMD ["npm", "run", "start"]
