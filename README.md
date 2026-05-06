# minbin

a minimal, ephemeral pastebin.

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fsolomonshalom%2Fminbin&project-name=minbin&repository-name=minbin&env=APP_DOMAIN&envDescription=Public%20domain%20used%20in%20generated%20paste%20URLs%20%28e.g.%20your-app.vercel.app%29&stores=%5B%7B%22type%22%3A%22kv%22%7D%5D)

## use

```bash
# share a string
curl -d "hello from the terminal" https://your-deployment

# share a file
curl --data-binary @file.txt https://your-deployment
```

## environment

| Variable         | Default      | Description                            |
| ---------------- | ------------ | -------------------------------------- |
| `APP_DOMAIN`     | `minb.in`    | public domain used in generated links  |
| `REDIS_URL`      | *(unset)*    | full redis connection string (preferred; auto-set by Vercel KV / Upstash) |
| `DB_HOST`        | `dragonfly`  | redis host (used when `REDIS_URL` is unset) |
| `DB_PORT`        | `6379`       | redis port                             |
| `DB_USER`        | *(optional)* | redis username                         |
| `DB_PASS`        | *(optional)* | redis password                         |
| `PASTE_EXPIRY`   | `60`         | paste expiry in **minutes**            |
| `MAX_PASTE_SIZE` | `5242880`    | max paste size in **bytes** (5 MB)     |

## self-host

```bash
docker compose up
```

or run it locally:

```bash
npm install
npm run build
npm start
```

## credit

based on [minbin](https://github.com/berrysauce/minbin) by [berrysauce](https://berrysauce.dev/) — this fork is a TypeScript / Fastify rewrite of the original Python / FastAPI backend.

licensed under [GPL-3.0](LICENSE).
