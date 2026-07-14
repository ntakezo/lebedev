# Lebedev

![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)

Lebedev is a lightweight man-in-the-middle proxy that **mirrors the client it
intercepts**. Instead of re-originating traffic with its own fingerprint, it
reconstructs the captured client's TLS ClientHello and HTTP/2 traits and replays
them upstream, so the origin sees a connection that matches the real client —
while every request and response is streamed out as structured, faithful data
for inspection.

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
- **Structured streaming** — one JSON record per transaction, to stdout or a file.
- **Multi-session support** — tag and route traffic per session, optionally
  through a per-session outbound proxy.
- **Simple CA management** — generate a root CA and print OS-specific trust
  instructions with one command.
- **Small and dependency-light** — a single Go binary, no runtime services.

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
                            JSON Lines session data
```

1. A client is configured to use Lebedev as its HTTPS proxy and issues `CONNECT`.
2. Lebedev peeks the raw TLS ClientHello (for fingerprinting), then terminates
   TLS with a leaf certificate minted on the fly for the requested host and
   signed by the local root CA.
3. It parses the request without canonicalizing order, casing, or body.
4. It forwards the request to the origin through an upstream client whose TLS and
   HTTP/2 fingerprint reproduce the captured client.
5. The origin's response is returned to the client, and the full transaction is
   emitted as a structured record.

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

**1. Create and trust the root CA.** Lebedev must terminate TLS, so its root has
to be trusted by the client machine. `cert` generates the CA (on first run) and
prints the command to trust it:

```sh
lebedev cert
```

On macOS, for example, it prints:

```sh
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.lebedev/ca.crt
```

**2. Start a proxy session:**

```sh
lebedev run --addr :8080 --out session.jsonl --session my-app
```

**3. Point a client at it.** Any client that speaks HTTP `CONNECT` works — set it
as the HTTPS proxy. For a real browser fingerprint, configure the browser's proxy
to `localhost:8080`. With curl:

```sh
curl -x http://localhost:8080 --cacert ~/.lebedev/ca.crt https://example.com/
```

Or launch a fresh, isolated Chrome already pointed at the proxy — a clean profile
with no cookies, history, or extensions, so the capture reflects a real browser's
fingerprint:

```sh
lebedev browser
```

It opens `https://tls.peet.ws/api/all` by default so you can eyeball the JA3/JA4 the
origin sees; pass `--url` for anything else. Closing Chrome discards the profile.

Each request/response is written to `session.jsonl` as it completes.

### Filtering what gets recorded

By default every transaction is written. `--filter-url` and `--filter-type` narrow
the output (capture and upstream mirroring are unaffected — only what reaches the
sink changes). Both flags are repeatable; within a flag the matches are OR'd, and
the two flags are AND'd together.

```sh
# only HTML documents
lebedev run --filter-type html

# only images and fonts from any fifa.com host
lebedev run --filter-type image --filter-type font --filter-url '*fifa.com*'

# only .json responses under /api/
lebedev run --filter-url '*//*/api/*' --filter-type json
```

URL globs match the full `scheme://authority/target` with `*` matching any run of
characters (including `/`), so `*//*/*` matches any absolute URL. Type values are
friendly categories (`html`, `image`, `json`, `css`, `js`, `font`, `media`,
`video`, `audio`, `xml`, `text`) or a raw MIME glob such as `image/*` or
`text/html`; a response with no `Content-Type` never matches a `--filter-type`.

## Usage

```
lebedev run     [flags]   start a proxy session
lebedev cert    [flags]   ensure the CA exists and print trust instructions
lebedev browser [flags]   launch a fresh Chrome routed through the proxy
```

### `run` flags

| Flag              | Default            | Description                                            |
| ----------------- | ------------------ | ------------------------------------------------------ |
| `--addr`          | `:8080`            | Listen address for the HTTP `CONNECT` proxy.           |
| `--out`           | `-`                | Session output: `-` for stdout, or a file path.        |
| `--session`       | `default`          | Session id recorded on each transaction.               |
| `--upstream-proxy`| _(none)_           | Outbound proxy URL for origin traffic, e.g. `http://host:port`. |
| `--filter-url`    | _(none)_           | Only record request URLs matching this glob (`*` matches any chars, including `/`). Repeatable. |
| `--filter-type`   | _(none)_           | Only record responses of this content type. Repeatable. |
| `--ca-cert`       | `~/.lebedev/ca.crt`| Path to the root CA certificate.                       |
| `--ca-key`        | `~/.lebedev/ca.key`| Path to the root CA private key.                       |

### `cert` flags

| Flag        | Default             | Description                       |
| ----------- | ------------------- | --------------------------------- |
| `--ca-cert` | `~/.lebedev/ca.crt` | Path to the root CA certificate.  |
| `--ca-key`  | `~/.lebedev/ca.key` | Path to the root CA private key.  |

The CA is generated on first use and reused thereafter. Keep `ca.key` private; it
can mint a trusted certificate for any host.

### `browser` flags

| Flag                 | Default                        | Description                                             |
| -------------------- | ------------------------------ | ------------------------------------------------------- |
| `--proxy`            | `http://127.0.0.1:8080`        | Lebedev proxy URL Chrome routes through.                |
| `--url`              | `https://tls.peet.ws/api/all`  | Initial URL to open.                                    |
| `--chrome`           | _(auto-detected)_              | Path to the Chrome binary; overrides autodetection.     |
| `--user-data-dir`    | _(fresh temp dir)_             | Chrome profile directory; a temp profile is used and removed on exit when empty. |
| `--ignore-cert-errors`| `false`                       | Ignore TLS cert errors instead of trusting the CA.      |

Chrome is found via `--chrome`, then the `LEBEDEV_CHROME` environment variable,
then `PATH`, then the platform's default install locations. Because Chrome must
trust the proxy's leaf certificates, either trust the CA first (`lebedev cert`) or
pass `--ignore-cert-errors` for a throwaway run. On macOS, trusting the CA in the
System keychain covers Chrome; on Linux, Chrome uses its own NSS store, so
`--ignore-cert-errors` is the simplest path.

## Session output format

Sessions are emitted as [JSON Lines](https://jsonlines.org/) — one record per
completed transaction. The `http2` object is present only for HTTP/2 connections;
`clientHelloHex` is the raw ClientHello record, hex-encoded. The response's
`proto` field is present only when the upstream protocol differs from the client's
request protocol — that is, when the mirror upgraded the origin to `HTTP/3.0`.
Bodies are the raw bytes as sent on the wire (not decompressed), carried as a
JSON string.

```json
{
  "session": "my-app",
  "protocol": "HTTP/2.0",
  "tls": { "clientHelloHex": "1603010200010001fc0303..." },
  "request": {
    "method": "GET",
    "target": "/",
    "scheme": "https",
    "authority": "example.com",
    "proto": "HTTP/2.0",
    "headers": [
      { "name": "user-agent", "value": "Mozilla/5.0" },
      { "name": "accept", "value": "text/html" }
    ]
  },
  "response": {
    "status": 200,
    "headers": [{ "name": "content-type", "value": "text/html" }],
    "body": "<!doctype html>..."
  },
  "http2": {
    "settings": [
      { "id": 1, "value": 65536 },
      { "id": 4, "value": 6291456 }
    ],
    "connectionFlow": 15663105,
    "pseudoOrder": [":method", ":authority", ":scheme", ":path"],
    "headerOrder": ["user-agent", "accept"]
  }
}
```

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
| `session`  | Ties a proxy run to a serialized session data stream.                |

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
