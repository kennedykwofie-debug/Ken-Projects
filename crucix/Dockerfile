FROM node:22-alpine
WORKDIR /app

# Copy package files
COPY crucix/package.json crucix/package-lock.json* ./
RUN npm install --production 2>/dev/null || npm install

# Copy ALL crucix source explicitly
COPY crucix/server.mjs .
COPY crucix/crucix.config.mjs .
COPY crucix/railway.json .
COPY crucix/nixpacks.toml* ./
COPY crucix/apis ./apis
COPY crucix/lib ./lib
COPY crucix/locales ./locales
COPY crucix/dashboard ./dashboard

EXPOSE 3117
CMD ["node", "server.mjs"]
