# sec4.si Metric

Metric is the reading analytics service for [sec4.si](https://sec4.si). It stores daily anonymous visit counts and GitHub reading records that readers choose to submit. The dashboard supports filtering by article and by 7, 30, or 90 days.

## Access

The dashboard checks active GitHub organization owner status in `sec4si` on each protected request. GitHub handles can change, so the three core roles use stable account IDs:

| Core administrator | GitHub ID |
| --- | ---: |
| `ZacharyZcR` | 48591714 |
| `VillanCh` | 13946521 |
| `winmin` | 18380453 |

Core administrators may suspend or restore other current owners' dashboard access. Membership changes on GitHub apply to existing sessions on their next request. Dashboard sign-in requests GitHub's `read:org` scope. The reader login uses public identity and asks for a separate confirmation before recording a visit.

Article pages submit their canonical path to `POST /api/views`. The service permits the configured article origin, honors Do Not Track and Global Privacy Control signals, and stores the path, day, and count. The browser request uses no credentials or referrer. Confirmed reader records store the GitHub account ID, handle, path, and day. Both forms of analytics are kept for 90 days. The visit count measures page views. The confirmed records show who chose to leave a record and can be filtered separately.

## Local development

Go 1.27.4 and SQLite via `modernc.org/sqlite`. The binary includes the HTML templates and fonts. SQLite stores data in `data/metric.sqlite` by default.

```sh
go test ./...
go run .
```

Open [the local site](http://127.0.0.1:9841/). Without a GitHub OAuth configuration, the home, privacy, ingestion, and health endpoints are available. The integration tests exercise the OAuth exchange and owner and reader flows against a local GitHub fixture.

## Production setup

1. Create a DNS-only A record for `metric.sec4.si` pointing to the server. Route HTTPS to `127.0.0.1:9841` on the server. The reverse proxy should set `X-Real-IP` to the source address, keep access logging disabled for this hostname, and obtain a trusted certificate. [Caddy example](ops/metric.caddy)
2. Generate a dedicated Ed25519 SSH key for the workflow. As root on the target host, run `bash ops/bootstrap.sh /path/to/metric-deploy.pub` with its public key. This installs the systemd service and a deployment account whose key can call only the release installer. The service runs as `sec4si-metric` and keeps its database in `/var/lib/sec4si-metric`.
3. Register the `sec4si Metric` OAuth app under the GitHub organization. Set its home URL to `https://metric.sec4.si/` and callback URL to `https://metric.sec4.si/oauth/callback`. Put `METRIC_GITHUB_CLIENT_ID` in `/etc/sec4si-metric/metric.env`. Store the client secret in a root-readable `/etc/sec4si-metric/github-oauth` file and add a systemd service drop-in with `LoadCredential=github-oauth:/etc/sec4si-metric/github-oauth` under `[Service]`. Reload systemd after adding the drop-in.
4. In the repository, set the `production` environment secret `METRIC_DEPLOY_KEY` to the CI private key. Set repository variables `METRIC_SSH_HOST`, `METRIC_SSH_PORT` if different from 22, and `METRIC_KNOWN_HOSTS` to the verified OpenSSH server host key line. Set `METRIC_GOARCH` to `arm64` only for an ARM64 server. Set `METRIC_DEPLOY_READY=true` after the server and proxy are ready.
5. Trigger [Metric CI and deployment](../../actions/workflows/deploy.yml) from `main`. The job tests, compiles, and pushes the release over SSH. The installer switches binaries and restores the prior one if the origin fails its health check. The workflow verifies the deployed revision through public HTTPS. Deploys keep the SQLite database in place.
6. Check `https://metric.sec4.si/healthz` for `oauth_ready: true`, try GitHub login as an organization owner, and verify a confirmed read from the article site.

For a proxy already listening on 80 and 443, add the hostname to that proxy. The example uses public ACME certificate issuance through Caddy. GitHub Actions uses a pinned SSH server key. OAuth secrets belong on the target server.

The code is MIT licensed. The fonts use the SIL Open Font License, available in `licenses/`.
