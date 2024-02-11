FROM node:20-slim

RUN corepack enable && \
    mkdir -p /app && \
    useradd -m app && \
    chown -R app:app /app

USER app
COPY . /app
WORKDIR /app
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile

# kill -9 -1 is a hack to force the container to restart if the healthcheck fails
HEALTHCHECK --interval=20s --timeout=5s \
    CMD node /app/healthcheck.js || kill -9 -1 

CMD ["pnpm", "start"]