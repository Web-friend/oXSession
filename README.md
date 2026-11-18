# oXSession Auth Service

A small standalone Axum service that provides the foundation for authentication work.

## Prerequisites

- Rust and Cargo (stable toolchain)

## Run locally

```sh
cargo run
```

The service listens on `127.0.0.1:3000` by default. Check it with:

```sh
curl http://127.0.0.1:3000/health
```

The response is `200 OK` with JSON: `{"status":"ok"}`.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `AUTH_BIND_ADDR` | `127.0.0.1` | IP address to bind to |
| `AUTH_PORT` | `3000` | TCP port to listen on (1–65535) |

Set variables in the shell before running `cargo run`. The service does not load dotenv files.

## Initial architecture decisions

- Run as a standalone Rust service using Axum and Tokio.
- Use Google OpenID Connect as the first identity provider.
- Use PostgreSQL as the first database, with migrations.
- Keep v1 focused on issuing JWTs.

PostgreSQL, migrations, provider identity modeling, OAuth callbacks, and JWT issuance are planned for the next implementation stage.
