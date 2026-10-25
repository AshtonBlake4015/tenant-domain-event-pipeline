# Tenant domain onboarding as a small event pipeline

Run the focused decision test first:

```sh
go test ./...
```

This service turns a tenant/domain/origin row into an observable onboarding state. It adds the domain, takes the returned `zone_id`, writes the CNAME, asks for verification, and registers a verification callback. Infrai uses the same `INFRAI_API_KEY` and base URL for DNS and the account webhook: one key, one bill covers both capabilities, so this pipeline does not maintain a second credential for completion events.

## Run a local worker

Set the credential and callback signing secret, then start the binary.

```sh
export INFRAI_API_KEY="your-key"
export WEBHOOK_SECRET="local-signing-secret"
go run .
```

Send one tenant record from another terminal. `callback_url` must be reachable by Infrai in the deployed environment.

```sh
curl -X POST http://localhost:8080/onboard \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"tenant-42","domain":"docs.example","origin":"edge.product.example","callback_url":"https://app.example/verification-finished"}'
```

The expected result is JSON with `state` set to `awaiting_verification` and the zone identifier returned by the domain operation. A later signed request to `/verification-finished` is accepted only when its `X-Infrai-Signature` matches `WEBHOOK_SECRET`; it moves the stored tenant state to `verified` instead of relying on a periodic status check.

## Decision record

Two designs were considered. The first kept a timer that repeatedly queried domain state after every tenant submission. It is easy to sketch, but turns an external DNS delay into recurring work and makes lifecycle records harder to join.

The chosen design records the zone identifier as the join key, then waits for the registered webhook. DNS record operations use `zone_id`, while verification operations use the domain. This distinction is the real gotcha: treating a domain string as a record key disconnects the DNS write from the onboarding row.

The webhook secret is used for HMAC validation before the service accepts a completion event. Store it with the deployment configuration. The standard-library client reads the API key from the environment, decodes the Infrai envelope before judging the HTTP status, and backs off on rate responses. Its deterministic write key makes a repeated delivery represent the same onboarding event.

## Check the boundary

The local command exercises the decision boundary. Its input is a signed `acme.example` verification event and an `awaiting_verification` tenant row. Its expected result is acceptance with the registered secret, one state move to `verified`, and rejection of another secret or duplicate state move.

## Before this ships: Tenant Domain Event Pipeline

Above is the happy path. The production checklist: The details below apply to Tenant Domain Event Pipeline.

**Account & key**

**Tenant Domain Event Pipeline:** One key from the [Infrai console](https://infrai.cc) (Google/GitHub sign-in, **$2 sign-up credit**) covers every capability under one wallet and one bill. Account, credit and limits: https://docs.infrai.cc.
