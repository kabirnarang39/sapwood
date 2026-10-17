# Webhooks

A repository on a platform server (`pandod server --platform`) can call URLs when something
happens in it, so CI, chat and issue trackers react to Pando the way they react to GitHub.

```sh
pando webhook add lumen/fleet https://ci.example.com/hooks/pando --event push --event change_request
pando webhook ping ID        # sends a ping now and shows the answer
pando webhook log ID         # recent deliveries
```

Or in the console: repository **Settings → Webhooks** (repository administrators).

## Events

| Event | Sent when | `action` |
|---|---|---|
| `push` | a branch is created or moved (a land, a push, a rebase) | `created`, `updated` |
| `change_request` | a change request is opened, closed or landed | `opened`, `closed`, `landed` |
| `review` | someone reviews | `approved`, `requested changes`, `commented` |
| `comment` | someone comments | `created` |
| `check` | CI reports a check | `reported` |
| `ping` | you ping the webhook | `ping` |

A webhook with no events listed receives every event.

## Requests

`POST` with a JSON body and these headers:

| Header | Value |
|---|---|
| `X-Pando-Event` | the event, e.g. `push` |
| `X-Pando-Delivery` | a unique id for this delivery; retries keep it |
| `X-Pando-Signature-256` | `sha256=` and the hex HMAC-SHA256 of the body, keyed with the webhook's secret |

Every body has `event`, `action`, `delivery`, `repository` (`owner`, `name`, `full_name`),
`sender` and `at_ms`. A `push` adds `ref`, `before`, `after` and `head` (`id`, `author`,
`message`); change request events add `change_request` (`number`, `title`, `author`,
`state`, `source`, `target`, `source_tip`, `base`, `draft`), and a landing adds `landed_as`;
`check` adds `check` (`name`, `state`, `summary`, `details_url`).

## Verifying the signature

The signature is computed exactly as GitHub computes `X-Hub-Signature-256`, so existing
libraries work. Compare in constant time, over the raw body:

```js
// Node
const crypto = require("node:crypto");
const ok = (secret, body, header) => {
  const want = "sha256=" + crypto.createHmac("sha256", secret).update(body).digest("hex");
  return header.length === want.length && crypto.timingSafeEqual(Buffer.from(header), Buffer.from(want));
};
```

```python
# Python
import hashlib, hmac
def ok(secret: bytes, body: bytes, header: str) -> bool:
    want = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header)
```

```go
// Go
func ok(secret, body []byte, header string) bool {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return hmac.Equal([]byte("sha256="+hex.EncodeToString(m.Sum(nil))), []byte(header))
}
```

## Delivery

- Answer with any 2xx within 10 seconds. Anything else is retried with growing gaps (10 s up
  to about 20 minutes), eight attempts in all; redirects are not followed.
- Deliveries are queued in the registry and claimed with a lease, so several server replicas
  never send the same delivery twice, and a restart loses none.
- Webhooks never call link-local, unspecified, multicast or reserved addresses, or cloud
  metadata services (169.254.169.254, 100.100.100.200, fd00:ec2::254), including IPv4 addresses
  written as IPv6 (mapped, NAT64, 6to4). By default they don't call loopback or private networks
  (RFC 1918, 100.64.0.0/10, fc00::/7) either; a self-hosted server whose CI lives there starts
  with `--webhook-allow-private`. The address is checked when the webhook is saved and again at
  every delivery, and the delivery connects only to the address it checked, so a DNS answer that
  changes in between can't redirect it.
- A failed delivery reports the HTTP status, or only "unreachable": never why a connection
  failed, so webhooks can't be used to probe the server's network.
- Each repository may have up to 20 webhooks; the last 200 deliveries of each are kept.
