FROM node:20-alpine as base


FROM base as dev

# todo-james remove, was maybe only needed for ava watch?
RUN apk add inotify-tools

RUN apk add bash

# todo-james only really needed for server-tests, use build target later?
RUN apk update && \
	apk add --no-cache \
	openssh-keygen

CMD bash -c 'npm install && npm run dev'