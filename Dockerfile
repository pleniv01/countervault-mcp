FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY server/ ./server/
COPY public/ ./public/
ENV NODE_ENV=production
USER node
CMD ["node", "server/index.mjs"]
