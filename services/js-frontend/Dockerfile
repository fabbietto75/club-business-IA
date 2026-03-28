FROM node:20-alpine

WORKDIR /app

COPY package.json .
RUN npm install

COPY server.js .

EXPOSE 3000

# exec node (non npm start): su Render il SIGTERM al redeploy non finisce nei log come "npm error"
CMD ["sh", "-c", "export PORT=${PORT:-3000} && exec node server.js"]
