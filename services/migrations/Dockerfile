FROM node:16-alpine as base

WORKDIR /usr/src/app

RUN apk add inotify-tools

RUN echo '{ "type": "module" }' > 'package.json'

# https://github.com/JAForbes/pgmg/commit/e77436e6b93b39f0a4367db2352c29e3076c813d
RUN npm install JAForbes/pgmg#e77436e6b93b39f0a4367db2352c29e3076c813d

FROM base as dev

RUN npm install nodemon

CMD ["npx", "nodemon", "-L", "--watch", "./migrations/*.js","--watch", "./tests/*.js", "--exec", "$(npm bin)/pgmg", "$DATABASE_URL", "migrations/*.js", "--dev"]

FROM base as prod

CMD ["sh", "-c", "npx pgmg \"$DATABASE_URL\" migrations/*.js"]

FROM busybox as default

CMD ["echo", "Must be run with dev|prod docker build target"]