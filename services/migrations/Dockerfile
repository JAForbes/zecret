FROM node:20-alpine as base

WORKDIR /usr/src/app

RUN apk add inotify-tools

FROM base as dev

HEALTHCHECK --interval=30s --timeout=5s --retries=1000 CMD stat health-check.txt

CMD npm install && npx tsx --watch node_modules/.bin/pgmg $DATABASE_URL ./migrations/* --dev --health-check-file ./health-check.txt

FROM base as prod

CMD npm install && npx pgmg $DATABASE_URL migrations/* --prod 

FROM busybox as default

CMD ["echo", "Must be run with dev|prod docker build target"]