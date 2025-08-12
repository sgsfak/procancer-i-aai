FROM node:18

# RUN mkdir -p /usr/src/app/node_modules && chown -R node:node /usr/src/app
WORKDIR /usr/src/app
COPY package*.json ./

# USER node
RUN npm install

# COPY --chown=node:node . .
COPY . .

EXPOSE 3000
CMD [ "npm", "start" ]