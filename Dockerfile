FROM node:22-alpine AS base

FROM base AS builder
RUN apk update
RUN apk add --no-cache libc6-compat

# Set working directory
WORKDIR /app

COPY ./package.json ./package.json

# Install dependencies
RUN npm install

RUN npm dedupe

COPY . .

RUN npm run build

FROM base AS runner
WORKDIR /app

COPY --from=builder /app/dist .
COPY --from=builder /app/package.json /app/package-lock.json .      
RUN npm install --omit=dev            

# Don't run production as root
RUN addgroup --system --gid 1001 expressjs
RUN adduser --system --uid 1001 expressjs
USER expressjs

EXPOSE 5000

CMD  node index.js