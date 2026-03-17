FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY src/ ./src/
COPY .env.example .env.example
RUN mkdir -p logs
EXPOSE 3001
CMD ["node", "src/server.js"]
