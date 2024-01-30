FROM node:20-alpine as base


FROM base as dev

# todo-james remove, was maybe only needed for ava watch?
RUN apk add inotify-tools

RUN apk add bash curl

# todo-james only really needed for server-tests, use build target later?
RUN apk update && \
	apk add --no-cache \
	openssh-keygen

HEALTHCHECK --interval=5s --timeout=3s \
	CMD curl http://localhost:8080/health

CMD bash -c 'npm install && npm run dev'