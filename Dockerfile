FROM node:current-alpine3.17

WORKDIR /home/cycclon/Projects/rioja-recursos/backend/usuarios

COPY . /home/cycclon/Projects/rioja-recursos/backend/usuarios

RUN npm install

EXPOSE 3001

CMD npm run Start