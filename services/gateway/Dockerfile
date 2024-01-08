FROM node:20.5.1

ENV APP_NAME cutcutfilm
ENV APP_HOME /app/${APP_NAME}/services/gateway
WORKDIR "$APP_HOME"

COPY package*.json ./

RUN npm install -g pm2
RUN npm install

COPY . .

RUN npm run build

CMD [ "pm2-runtime", "npm", "--", "start" ]