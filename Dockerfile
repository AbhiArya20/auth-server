FROM node:22-alpine AS base

FROM base AS builder
RUN apk update
RUN apk add --no-cache libc6-compat

# Set working directory
WORKDIR /app

RUN if ! command -v yarn &> /dev/null; then npm install -g yarn; fi

COPY ./package.json ./package.json

# Install dependencies
RUN yarn install

COPY . .

RUN npm run build

FROM base AS runner
WORKDIR /app

# Don't run production as root
RUN addgroup --system --gid 1001 expressjs
RUN adduser --system --uid 1001 expressjs
USER expressjs
COPY --from=builder /app/dist .

CMD node app/dist/index.js