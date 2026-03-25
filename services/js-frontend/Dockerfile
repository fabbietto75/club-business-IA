FROM node:20-alpine

WORKDIR /app

COPY package.json .
RUN npm install

COPY server.js .

EXPOSE 3000

CMD ["sh", "-c", "export PORT=${PORT:-3000} && exec npm start"]
