# Lebedev

![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)

Lebedev is a lightweight man-in-the-middle proxy that **never re-originates
traffic with a proxy fingerprint**. Origin requests go out over an fhttp
tls-client wearing the stock latest-Chrome profile (`Chrome_150_PSK`), while
every request and response is recorded as structured, faithful data for
inspection — including the TLS ClientHello and HTTP/2 traits of the client that
was intercepted.

It is built for debugging and analyzing HTTPS traffic where a generic proxy would
be detected or would alter the very behavior you are trying to observe.

## Features

- **Browser-fingerprinted upstream** — sends origin traffic with tls-client's
  stock latest-Chrome profile, so the origin sees a real browser's ClientHello
  and HTTP/2 SETTINGS rather than a proxy's.
- **Faithful capture** — preserves header order, header casing, and body bytes
  across HTTP/1.1 and HTTP/2, and records the intercepted client's own JA3/JA4
  ClientHello and h2 fingerprint per connection.
- **SQLite-backed store** — the HAR 1.3 model laid out for SQLite behind a small
  repository. It round-trips every observation verbatim — header and cookie
  order, whitespace, URLs, form fields, and bodies — and stores one row per TLS
  connection instead of repeating a fingerprint on every entry.
- **Interactive REPL** — a single prompt to start captures and CRUD stored
  sessions. Built for a developer at the keyboard and for an LLM driving it
  through an MCP server.
- **In-memory captures** — a capture's session lives in memory and is discarded
  on exit; `save` it to the durable store (or export it to HAR) to keep it. The
  durable store itself survives across runs.
- **HAR 1.3 import/export** — sessions export as a standard HTTP Archive (HAR)
  1.3 document and existing HAR files import back in. The raw TLS ClientHello and
  HTTP/2 fingerprint ride along in a custom `_lebedev` field.
- **Small and dependency-light** — a single Go binary (pure-Go SQLite, no CGo).

## How it works

```
                          Lebedev
  ┌────────┐   CONNECT   ┌──────────────────────────┐  stock Chrome ┌────────┐
  │ client │────────────▶│  terminate TLS w/ leaf    │  ClientHello  │ origin │
  │ (proxy │   HTTPS      │  peek + fingerprint hello │──────────────▶│ server │
  │  set)  │◀────────────│  capture request faithfully│◀──────────────│        │
  └────────┘   response   │  forward as latest Chrome  │   response    └────────┘
                          └──────────────────────────┘
                                      │
                                      ▼
                     SQL store  ──▶  HAR 1.3 export / query
```

1. A client is configured to use Lebedev as its HTTPS proxy and issues `CONNECT`.
2. Lebedev peeks the raw TLS ClientHello (for fingerprinting), then terminates
   TLS with a leaf certificate minted on the fly for the requested host and
   signed by the local root CA.
3. It parses the request without canonicalizing order, casing, or body.
4. It forwards the request to the origin through an upstream client whose TLS and
   HTTP/2 fingerprint is the stock latest-Chrome profile.
5. The origin's response is returned to the client, and the full transaction is
   recorded as a HAR entry — queryable and exportable on demand.

## Install

With the Go toolchain (Go 1.25+):

```sh
go install github.com/ntakezo/lebedev/cmd/lebedev@latest
```

Or build from source:

```sh
git clone https://github.com/ntakezo/lebedev
cd lebedev
go build -o lebedev ./cmd/lebedev
```

## Quick start

Running `lebedev` opens an interactive REPL. Startup ensures the root CA exists
and opens the durable store (`~/.lebedev/lebedev.db` by default).

```sh
lebedev
lebedev: durable store ~/.lebedev/lebedev.db (CA: ~/.lebedev/ca.crt)
lebedev: type 'help' for commands
lebedev>
```

**1. Trust the root CA.** Lebedev must terminate TLS, so its root has to be
trusted by the client machine. `cert` prints the command to trust it:

```
lebedev> cert
CA certificate: ~/.lebedev/ca.crt

Trust it (admin required):
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.lebedev/ca.crt
```

**2. Start a capture.** `run` begins serving the proxy; the session's entries
accumulate in memory:

```
lebedev> run my-app --addr :8080
capturing session "my-app" on [::]:8080 — entries are in memory only ('save' to keep them)
```

**3. Point a client at it.** Any client that speaks HTTP `CONNECT` works — set it
as the HTTPS proxy. With curl:

```sh
curl -x http://localhost:8080 --cacert ~/.lebedev/ca.crt https://example.com/
```

Or launch a fresh, isolated Chrome already pointed at the active capture — a clean
profile with no cookies, history, or extensions:

```
lebedev> browser
```

**4. Keep it, or let it go.** The session vanishes when you quit. To keep it,
`save` it to the durable store — or export it to a HAR file:

```
lebedev> save
saved session "my-app" to the durable store (12 entries)
lebedev> export my-app my-app.har
```

## The REPL

The durable store (the "system state") is opened for the life of the process and
survives across runs. A capture's session, by contrast, lives in memory and is
discarded on exit; to keep it, `save` it to the durable store (or `export` it to a
HAR file). Re-running `save` overwrites the stored copy, so it snapshots the
growing session without duplicating entries.

```
run [id] [--addr :8080] [--upstream-proxy URL]
                       start a capture; entries stay in memory only
save                   write the live session to the durable store
stop <id>              stop the capture (its session stays queryable)
resume <id>            resume a stopped capture on its address
sessions | ls          list stored sessions (and the live one, if any)
show <id> [limit]      list a session's entries
export <id> [file]     write a session as HAR 1.3 (stdout if no file)
import <file> [as id]  load a HAR 1.3 document into the durable store
rename <old> <new>     rename a stored session
rm <id>                delete a stored session
cert                   print CA trust instructions
browser [url]          launch a fresh Chrome through the active capture
help | quit
```

`run` takes an optional session id (default `default`), the listen address, and
an optional per-session outbound proxy.

`stop <id>` pauses the capture named by
id, leaving its in-memory session queryable; `resume <id>` re-serves it on the
same address, appending new transactions to the same session. `save` writes the
active capture to the durable store; `show`, `export`, and `sessions` operate on
the live in-memory session when the id names the active capture, and on the
durable store otherwise.

### Global flags

| Flag        | Default                   | Description                                            |
| ----------- | ------------------------- | ------------------------------------------------------ |
| `--db`      | `~/.lebedev/lebedev.db`   | Path to the durable SQLite store.                      |
| `--ca-cert` | `~/.lebedev/ca.crt`       | Path to the root CA certificate.                       |
| `--ca-key`  | `~/.lebedev/ca.key`       | Path to the root CA private key.                       |

The CA is generated on first use and reused thereafter. Keep `ca.key` private; it
can mint a trusted certificate for any host.

## Storage and HAR format

Transactions are recorded into SQLite (`~/.lebedev/lebedev.db` by default). A
capture's live session is held in an in-memory database and reaches the durable
store when you `save` it (or export it to HAR and import it back). The schema is
queryable directly, and the store round-trips every observation verbatim; any
transformation an observation needs to fit HAR (deriving a status text,
base64-encoding a binary body) is done before the store sees it, so the SQL layer
never alters the bytes it is handed.

The layout follows the wire rather than the document. A HAR file repeats a
connection's fingerprint on every entry; here one TLS connection is a row that
its entries reference, and each entry's `_lebedev` field is rebuilt from it on
read — same bytes out, stored once. Ordered lists (headers, cookies, query and
post parameters) are child rows carrying their position, so order, casing, and
repeated names survive instead of collapsing into a map. Tables are `STRICT`, so
SQLite rejects a mistyped value rather than coercing it, and ownership runs
through `ON DELETE CASCADE`.

Import and export use [HAR 1.3](http://www.softwareishard.com/blog/har-12-spec/),
the standard HTTP Archive format most browser devtools and proxies understand.
Lebedev-specific data that HAR has no home for — the session id, the raw TLS
ClientHello, the upstream protocol actually spoken, and the HTTP/2 fingerprint —
rides along in the custom, underscore-prefixed `_lebedev` field the HAR spec
reserves for tool extensions. Response bodies are HAR `content` (base64-encoded
with `"encoding": "base64"` when not valid UTF-8), so binary responses survive a
round trip byte-for-byte.

```json
{
  "log": {
    "version": "1.3",
    "creator": { "name": "lebedev", "version": "1.3" },
    "entries": [
      {
        "startedDateTime": "2026-07-13T00:00:00.000Z",
        "time": 0,
        "request": {
          "method": "GET",
          "url": "https://example.com/",
          "httpVersion": "HTTP/2.0",
          "cookies": [],
          "headers": [
            { "name": "user-agent", "value": "Mozilla/5.0" },
            { "name": "accept", "value": "text/html" }
          ],
          "queryString": [],
          "headersSize": -1,
          "bodySize": 0
        },
        "response": {
          "status": 200,
          "statusText": "OK",
          "httpVersion": "HTTP/2.0",
          "cookies": [],
          "headers": [{ "name": "content-type", "value": "text/html" }],
          "content": { "size": 559, "mimeType": "text/html", "text": "<!doctype html>..." },
          "redirectURL": "",
          "headersSize": -1,
          "bodySize": 559
        },
        "cache": {},
        "timings": { "send": 0, "wait": 0, "receive": 0 },
        "_lebedev": {
          "session": "my-app",
          "clientHelloHex": "1603010200010001fc0303...",
          "http2": {
            "settings": [{ "id": 1, "value": 65536 }, { "id": 4, "value": 6291456 }],
            "connectionFlow": 15663105,
            "pseudoOrder": [":method", ":authority", ":scheme", ":path"],
            "headerOrder": ["user-agent", "accept"]
          }
        }
      }
    ]
  }
}
```

## Fidelity and detection surface

Lebedev sends origin traffic with the stock latest-Chrome profile
(`Chrome_150_PSK`), which supplies the ClientHello, h2 SETTINGS, and
pseudo-header order. The captured request's headers, header order, casing, and
body are reproduced verbatim on top of it:

- **TLS ClientHello (JA3/JA4):** cipher suites, extensions, curves, and ALPN come
  from the Chrome profile, including real PSK resumption, so reconnects to an
  origin resume the way a revisiting browser's do.
- **HTTP/1.1 and HTTP/2:** header order and casing are preserved, including Host
  and Content-Length at their captured positions, plus chunked request framing.
- **Bodies:** request and response bodies are forwarded as sent — no injected
  `Accept-Encoding` and no transparent decompression.

Limitations to be aware of:

- **The client's own fingerprint is recorded, not replayed.** The intercepted
  ClientHello and h2 traits are captured and stored per connection, but origin
  traffic goes out as stock Chrome. A client that is not Chrome will present a
  Chrome fingerprint upstream.
- **TCP/IP stack and source IP:** the origin sees the proxy host's kernel TCP
  fingerprint (window size, options, TTL) and its IP, not the client's. Route
  egress through a matching environment (`--upstream-proxy`) to align this layer.
- **No HTTP/3:** origins are contacted over h2/h1 only; QUIC is left to the
  upstream rewrite.
- **Connection coalescing:** a browser may coalesce multiple hostnames onto one
  h2 connection; the upstream client opens one connection per origin authority.
- **Chunked request bodies** are re-chunked: the Transfer-Encoding framing is
  preserved, but the exact chunk boundaries are not.

## Development

```sh
go build ./...
go test ./...
go test -race ./...
```

The codebase is organized under `internal/`:

| Package    | Responsibility                                                        |
| ---------- | -------------------------------------------------------------------- |
| `ca`       | Root CA and per-host leaf certificate minting.                       |
| `proxy`    | MITM core: `CONNECT`, TLS termination, and upstream dispatch.        |
| `capture`  | Faithful HTTP/1.1 and HTTP/2 request parsing and fingerprinting.     |
| `upstream` | Stock latest-Chrome client that forwards requests to the origin.      |
| `session`  | Turns each connection and transaction into records for a recorder.   |
| `repl`     | Interactive control surface: captures, saving to the store, and session CRUD. |

Three packages are public, for consumers that want the model or the store
without importing anything internal:

| Package             | Responsibility                                                   |
| ------------------- | ---------------------------------------------------------------- |
| `har`               | The strict HAR 1.3 object model.                                 |
| `model`             | lebedev's extension of it: the capture fingerprint and store identity. |
| `repository`        | The persistence contract, implemented over SQLite in `repository/sqlite`. |

## Security and legal

Lebedev intercepts TLS traffic and requires its root CA to be trusted by the
client. That is a powerful capability:

- Only intercept traffic on systems and accounts you own or are explicitly
  authorized to test.
- The generated `ca.key` can forge a trusted certificate for any domain — store
  it securely and remove the CA from trust stores when you are done.
- Intercepting others' traffic without consent may be illegal in your
  jurisdiction. You are responsible for how you use this tool.

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
