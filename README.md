# zecret

A simple rewrite now that concepts are settled in my head.

## Local Development

To run tests:

```bash
docker compose -f docker-compose.tst.yml up --build
```

To run the app:

```bash
docker compose -f docker-compose.app.yml up --build
```

Tests and the app can run concurrently and each have their own local db instance.
