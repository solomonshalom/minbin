FROM node:25-alpine AS builder

WORKDIR /app

# Install dependencies (including dev for the build)
COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund

# Build TypeScript
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev


FROM node:25-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production \
    PORT=8000 \
    HOST=0.0.0.0

# Copy production dependencies and compiled output
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./package.json

# Templates and static assets
COPY templates ./templates

EXPOSE 8000

USER node

CMD ["node", "dist/server.js"]
