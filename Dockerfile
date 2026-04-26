FROM debian:trixie-slim AS build

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

RUN apt-get update && \
    apt-get install --no-install-suggests --no-install-recommends --yes python3-venv && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY pyproject.toml ldap_helper.py ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv /venv && \
    uv pip install --python /venv/bin/python .

FROM gcr.io/distroless/python3-debian13
COPY --from=build /venv /venv
ENTRYPOINT ["/venv/bin/ldap-helper"]
