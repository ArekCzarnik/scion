# Running Scion with Docker Compose

[`docker/compose.yml`](../docker/compose.yml) runs one `scion-server` with CockroachDB and MinIO.
The CLI is a separate image: it is not part of the stack and can run from any container that can
reach the server, or be installed natively.

The stack suits a single machine or a trusted network. CockroachDB and MinIO run as single nodes,
and CockroachDB runs in insecure mode because `scion-server` has no TLS client for its metadata
store. Neither backend publishes a port; keep it that way.

## Start the server

```sh
docker compose -f docker/compose.yml up -d --build --wait
```

The first build compiles the Rust workspace and takes several minutes. On first start the server
generates a token signing key, a private CA, a TLS certificate and the secret for the `agent`
service principal, and keeps them in Docker volumes. The server listens on
`https://localhost:7443`.

Settings are optional: copy [`docker/.env.example`](../docker/.env.example) to `docker/.env`.
[`docker/config`](../docker/config) holds the server config and access policy. Changes to
`acl.toml` apply while the server runs; after changing `scion-server.toml`, restart the service.

## Use the CLI

Build the CLI image once. [`docker/scion`](../docker/scion) runs it with the current directory
mounted, so paths must stay below that directory:

```sh
docker build -f docker/Dockerfile --target cli -t scion-cli:local .
docker/scion whoami
```

A new repository already has an empty `main`, so you can start working directly:

```sh
docker/scion checkout main work
echo hello > work/hello.txt
docker/scion -C work commit -m "Add greeting"
docker/scion -C work land --ref main
```

To start from an existing Git history instead, import it before anything lands on `main`:

```sh
docker/scion import --git . --ref HEAD --target-ref main
```

`docker/scion import` passes its arguments to `scion-import`; add `--skip-submodules` if the
history contains submodules. Importing again brings over only new commits. Once commits have
landed on `main`, a Git history that moved on independently is refused with `NOT_FAST_FORWARD`,
because Scion to Git is not a two-way sync; import it into another `--target-ref` instead.

Commands run as `service:agent`, which can read, write and land. `import` and `redact` run as
`service:admin`, which can also create refs, force-update `main` and redact content. Its secret
is in a separate volume that `docker/scion` mounts only for those two commands.

Set `SCION_AUTHOR` to record a commit author other than `service:agent`.

### From another container

Agents in other containers use the same image. Attach them to the `scion` network and mount the
`scion-client` volume, which holds only the CA certificate and agent secret. Do not mount
`scion-admin` into agent containers:

```yaml
services:
  agent:
    image: scion-cli:local
    command: ["log", "main"]
    networks: [scion]
    volumes:
      - scion-client:/var/lib/scion/client:ro

networks:
  scion:
    external: true

volumes:
  scion-client:
    external: true
```

### Native CLI

Build with Rust and `protoc` as described in the [README](../README.md#build), then fetch the
client material from the running server:

```sh
cargo install --locked --path crates/scion-cli
compose="docker compose -f docker/compose.yml"
$compose exec -T scion-server cat /var/lib/scion/client/ca.crt > scion-ca.pem

export SCION_ENDPOINT=https://localhost:7443
export SCION_CA_FILE=$PWD/scion-ca.pem
export SCION_SERVICE_SECRET=$($compose exec -T scion-server cat /var/lib/scion/client/agent.secret)
scion login --service agent
```

For `scion-import`, read `/var/lib/scion/admin/admin.secret` the same way and set
`SCION_SERVICE_NAME=admin`.

Service tokens last 12 hours by default; run `scion login` again after that. A working copy
remembers the endpoint it was checked out with, and the container and host use different ones
(`scion-server` and `localhost`), so use each working copy from the side that created it.

## Access from other machines

Set `SCION_BIND=0.0.0.0` and add the name that clients use to `SCION_TLS_HOSTS` in `docker/.env`,
then recreate the service with `up -d`. The server reissues its certificate from the same CA.

Clients then need `ca.crt` and a secret, as with the native CLI above. Give each client its own
principal rather than sharing `agent`: add a `[[auth.service_principals]]` block to
`scion-server.toml` and grant it access in `acl.toml`.

To let people log in, create a GitHub OAuth App with device flow enabled, set
`SCION_GITHUB_CLIENT_ID`, and add them to `acl.toml` as `github:<login>`.

## Operate

| Task | Command (prefix `docker compose -f docker/compose.yml`) |
| --- | --- |
| Follow server logs | `logs -f scion-server` |
| Read metrics | `exec scion-server curl -s http://127.0.0.1:9464/metrics` |
| Stop, keeping data | `down` |
| Delete all data and keys | `down -v` |

The named volumes hold everything, and both the metadata and the object volumes are needed to
restore a repository. See [backup and retention](operations/backup-retention.md).
