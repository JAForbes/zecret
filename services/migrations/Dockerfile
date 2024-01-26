FROM node:20-alpine as base

WORKDIR /usr/src/app

RUN apk add inotify-tools

RUN echo '{ "type": "module" }' > 'package.json'

# https://github.com/JAForbes/pgmg/commit/e77436e6b93b39f0a4367db2352c29e3076c813d
RUN npm install JAForbes/pgmg#e77436e6b93b39f0a4367db2352c29e3076c813d

FROM base as dev

RUN npm install tsx

HEALTHCHECK --interval=5s --timeout=1s CMD stat health-check.txt

CMD npx tsx --watch node_modules/.bin/pgmg $DATABASE_URL ./migrations/* --dev --health-check-file ./health-check.txt

FROM base as prod

CMD ["sh", "-c", "npx pgmg \"$DATABASE_URL\" migrations/*.js"]

FROM busybox as default

CMD ["echo", "Must be run with dev|prod docker build target"]