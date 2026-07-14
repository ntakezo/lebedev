# Lebedev

![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)

Lebedev is a lightweight man-in-the-middle proxy that **mirrors the client it
intercepts**. Instead of re-originating traffic with its own fingerprint, it
reconstructs the captured client's TLS ClientHello and HTTP/2 traits and replays
them upstream, so the origin sees a connection that matches the real client —
while every request and response is recorded as structured, faithful data for
inspection.

It is built for debugging and analyzing HTTPS traffic where a generic proxy would
be detected or would alter the very behavior you are trying to observe.

## Features

- **Fingerprint-mirroring upstream** — reproduces the client's JA3/JA4
  ClientHello and HTTP/2 SETTINGS, priorities, flow control, and header ordering.
- **HTTP/3 upgrade** — when an origin advertises HTTP/3 via `Alt-Svc`, the mirror
  upgrades that origin from h2 to h3 for subsequent requests, exactly as a real
  browser does, with a synthesized QUIC/h3 fingerprint matched to the client's
  browser family and a graceful h2 fallback when QUIC is blocked.
- **Faithful capture** — preserves header order, header casing, pseudo-header
  order, and body bytes across HTTP/1.1 and HTTP/2.
- **SQL-backed store** — transactions are recorded into SQL (SQLite or
  PostgreSQL) and queried on demand. The store round-trips every observation
  verbatim — header and cookie order, whitespace, URLs, form fields, and bodies.
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
  ┌────────┐   CONNECT   ┌──────────────────────────┐   mirrored    ┌────────┐
  │ client │────────────▶│  terminate TLS w/ leaf    │  ClientHello  │ origin │
  │ (proxy │   HTTPS      │  peek + fingerprint hello │──────────────▶│ server │
  │  set)  │◀────────────│  capture request faithfully│◀──────────────│        │
  └────────┘   response   │  replay upstream as client │   response    └────────┘
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
   HTTP/2 fingerprint reproduce the captured client.
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
and opens the durable store (`~/.lebedev/store.db` by default).

```sh
lebedev
lebedev: durable store sqlite:~/.lebedev/store.db (CA: ~/.lebedev/ca.crt)
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
an optional per-session outbound proxy. `stop <id>` pauses the capture named by
id, leaving its in-memory session queryable; `resume <id>` re-serves it on the
same address, appending new transactions to the same session. `save` writes the
active capture to the durable store; `show`, `export`, and `sessions` operate on
the live in-memory session when the id names the active capture, and on the
durable store otherwise.

### Global flags

| Flag        | Default                   | Description                                            |
| ----------- | ------------------------- | ------------------------------------------------------ |
| `--db`      | `sqlite:~/.lebedev/store.db` | Durable store DSN: `sqlite:PATH` or `postgres://…`. |
| `--ca-cert` | `~/.lebedev/ca.crt`       | Path to the root CA certificate.                       |
| `--ca-key`  | `~/.lebedev/ca.key`       | Path to the root CA private key.                       |

The CA is generated on first use and reused thereafter. Keep `ca.key` private; it
can mint a trusted certificate for any host.

## Storage and HAR format

Transactions are recorded into a SQL store — SQLite by default (`~/.lebedev/store.db`),
or PostgreSQL via `--db postgres://…`. A capture's live session is held in an
in-memory SQLite database and reaches the durable store when you `save` it (or
export it to HAR and import it back). The relational schema is queryable directly, and the store round-trips
every observation verbatim; any transformation an observation needs to fit HAR
(deriving a status text, base64-encoding a binary body) is done before the store
sees it, so the SQL layer never alters the bytes it is handed.

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

An upstream HTTP/3 upgrade shows up as `response.httpVersion` of `HTTP/3.0` and a
matching `_lebedev.upstreamProto`; for h2/h1 the field is omitted.

## Fidelity and detection surface

Lebedev reproduces the captured client toward the origin at several layers:

- **TLS ClientHello (JA3/JA4):** cipher suites, extensions, curves, and ALPN are
  reconstructed from the raw ClientHello.
- **TLS session resumption:** enabled for TLS 1.3 clients, so reconnects to an
  origin resume like a real revisiting browser instead of always full-handshaking.
- **HTTP/2:** SETTINGS (order and values), the initial connection flow-control
  window, PRIORITY frames, and pseudo-header/header order are mirrored. Streams
  are forwarded concurrently, so the origin sees the client's real multiplexing
  rather than a serialized one-request-at-a-time rewrite.
- **HTTP/3:** origins are contacted over h2 first; once an origin's `Alt-Svc`
  advertises `h3`, later requests to it race h3 (QUIC) against h2 and prefer
  whichever connects first — the same in-band discovery a browser performs.
  Because a proxied client reaches Lebedev over a TCP `CONNECT` tunnel, no real
  QUIC ClientHello is captured, so the upstream h3 fingerprint (QUIC transport
  parameters, h3 SETTINGS, pseudo-header order) is synthesized from the client's
  inferred browser family (Chrome/Chromium or Firefox) rather than mirrored bit
  for bit. The upstream protocol actually used is recorded per transaction.
- **HTTP/1.1:** header order and casing are preserved, including Host and
  Content-Length at their captured positions, plus chunked request framing.
- **Bodies:** request and response bodies are forwarded as sent — no injected
  `Accept-Encoding` and no transparent decompression.

Residual limitations a userspace mirror cannot remove:

- **TCP/IP stack and source IP:** the origin sees the proxy host's kernel TCP
  fingerprint (window size, options, TTL) and its IP, not the client's. Route
  egress through an environment matching the mirrored client (`--upstream-proxy`)
  to align this layer.
- **HTTP/2 flow-control cadence:** initial windows are mirrored, but the timing
  and size of subsequent WINDOW_UPDATE frames during large transfers are the
  upstream transport's, not the captured client's.
- **Connection coalescing:** a browser may coalesce multiple hostnames onto one
  h2 connection; the mirror opens one upstream connection per origin authority.
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
| `upstream` | Fingerprint-mirroring client that replays requests to the origin.    |
| `session`  | Turns each transaction into a HAR entry and hands it to a recorder.  |
| `store`    | SQL-backed persistence (SQLite/PostgreSQL) with HAR 1.3 import/export and querying. |
| `repl`     | Interactive control surface: captures, saving to the store, and session CRUD. |

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
