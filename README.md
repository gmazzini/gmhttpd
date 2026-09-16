# gmhttpd

gmhttpd is a small IPv4/IPv6 HTTPS web server written in C for simple CGI-based sites and a few controlled static/proxy use cases.

The design is intentionally minimal: one executable, one runtime `config` file, no per-directory configuration, no access log and no general-purpose module system.

## Build

Requirements:

- GCC
- OpenSSL development libraries

Build with:

```sh
make
```

The Makefile uses:

```text
-O3 -march=native -Wall -Wextra -Werror -std=gnu89
```

## Commands

```text
./gmhttpd help
./gmhttpd start
./gmhttpd server
./gmhttpd stats
./gmhttpd stop
```

`start` daemonizes the process and is useful for manual operation.

`server` stays in the foreground and is the correct mode under systemd.

`stats` reports uptime, accepted connections, active requests, valid HTTP requests, rejected connections, successfully served ACME challenges and per-vhost request counters.

## Configuration

gmhttpd reads `config` from its working directory.

The configuration must contain exactly one directive defining the HTTP and HTTPS ports:

```text
ports 80 443
```

An optional ACME directory can be configured for Certbot/Let's Encrypt HTTP-01 validation:

```text
acme acme
```

The path is relative to the gmhttpd working directory when a relative name is used. With the standard systemd setup above, `acme acme` means `/home/tools/mcp/work/gmhttpd/acme`. No hidden `.well-known` directory is created on disk.

HTTP requests are redirected to HTTPS with status `308 Permanent Redirect`, except valid `/.well-known/acme-challenge/<token>` requests when ACME support is configured.

There is no default virtual host. Unknown Host/SNI names are rejected.

### Normal virtual host

```text
host hostname root default-program certificate private-key
```

Example:

```text
host www.example.org /home/www/example app /etc/letsencrypt/live/www.example.org/fullchain.pem /etc/letsencrypt/live/www.example.org/privkey.pem
```

`/` executes or serves `default-program`. Other paths are resolved relative to `root`.

Executable regular files are run as CGI programs. File extensions are irrelevant for CGI execution.

Symlinks are followed deliberately, including symlinks whose final target is outside the document root.

### Host modes

An optional final field selects a special mode:

```text
host hostname root default certificate key catchall
host hostname root default certificate key phpcgi
host hostname root default certificate key csv
```

`catchall` executes the default program for every request path while preserving the original request URI.

`phpcgi` executes `.php` files through `/usr/bin/php-cgi`. Static files from the normal whitelist are still served directly. Other executable files are not executed in this mode.

`csv` enables static `.csv` downloads for that vhost only. CSV is intentionally not enabled globally.

### HTTPS redirect host

A host can exist only to redirect to another HTTPS URL:

```text
redirect old.example.org https://new.example.org/path certificate private-key
```

Both HTTP and HTTPS requests are answered with `308 Permanent Redirect`. The redirect host still needs its own TLS certificate for HTTPS clients.

### Reverse proxy

A path can be forwarded to an IPv4 HTTP backend:

```text
proxy hostname path backend-address backend-port backend-path bearer-token
```

Example:

```text
proxy www.example.org /mcp 127.0.0.1 8000 /mcp SECRET
```

The incoming request must contain exactly:

```text
Authorization: Bearer SECRET
```

The original HTTP headers are forwarded except for hop-by-hop/rewritten headers such as `Host` and `Connection`. The backend connection is closed after each request.

For deployments that keep the bearer token directly in `config`, protect the file:

```sh
chmod 600 config
```

The parser also accepts `@filename` in the bearer field and reads the first line of that file, but a single protected `config` file is sufficient for normal operation.

## Static files

Only explicitly supported file types are served. Unknown extensions return 404 rather than being exposed as generic files.

Globally supported types are:

```text
.html   text/html; charset=utf-8
.css    text/css; charset=utf-8
.js     application/javascript
.png    image/png
.jpg    image/jpeg
.jpeg   image/jpeg
.gif    image/gif
.ico    image/x-icon
.webp   image/webp
.ogg    audio/ogg
.pdf    application/pdf
.svg    image/svg+xml
.adi    application/octet-stream, attachment
.cbr    application/octet-stream, attachment
```

`.csv` is available only on hosts configured with the `csv` mode and is returned as an attachment.

There is no directory listing and no fallback for unknown file types.

## CGI

Supported request methods are:

```text
GET
HEAD
POST
```

The maximum request body size is 32 MiB. Chunked request bodies are rejected.

CGI programs receive the usual request information, including:

```text
GATEWAY_INTERFACE
SERVER_PROTOCOL
SERVER_SOFTWARE
SERVER_NAME
SERVER_PORT
HTTPS
REQUEST_METHOD
REQUEST_URI
QUERY_STRING
DOCUMENT_ROOT
SCRIPT_NAME
SCRIPT_FILENAME
HTTP_HOST
REMOTE_ADDR
HTTP_USER_AGENT
CONTENT_TYPE
CONTENT_LENGTH
HTTP_COOKIE
HTTP_RANGE
HTTP_X_AUTH_SIGNATURE
HTTP_X_HUB_SIGNATURE_256
HTTP_SEC_PURPOSE
```

`Status:` emitted by CGI is translated into the HTTP response status. HEAD responses suppress the body.

## ACME and Certbot

The optional `acme` directive removes the need for an Apache-based Certbot authenticator.

Example:

```text
acme acme
```

Certbot challenge tokens are stored directly as ordinary files in:

```text
/home/tools/mcp/work/gmhttpd/acme/<token>
```

The project includes two small Certbot hooks:

```text
auth   writes acme/$CERTBOT_TOKEN
clean  removes acme/$CERTBOT_TOKEN
```

They use the standard `CERTBOT_TOKEN` and `CERTBOT_VALIDATION` environment variables supplied by Certbot. This avoids a filesystem `.well-known` directory and removes the dependency on the Apache Certbot plugin.

gmhttpd exposes those files only on plain HTTP through the protocol-defined URL:

```text
/.well-known/acme-challenge/<token>
```

The `.well-known` component exists only in the public URL required by ACME; it is not created in the filesystem. Token names are restricted to letters, digits, `-` and `_`, and only regular files are served. GET and HEAD are accepted. All other HTTP paths keep their normal redirect behavior. Successfully served challenges are counted in the `acme` field of `gmhttpd stats`.

Certbot should use the `manual` authenticator with the two hooks above and a deploy hook that restarts `gmhttpd` after a successful renewal, because TLS certificates are loaded at server startup. For example:

```sh
certbot reconfigure --cert-name www.example.org \
  --authenticator manual \
  --preferred-challenges http \
  --manual-auth-hook /home/tools/mcp/work/gmhttpd/auth \
  --manual-cleanup-hook /home/tools/mcp/work/gmhttpd/clean \
  --deploy-hook "systemctl restart gmhttpd"
```

After a certificate renewal, gmhttpd must be restarted because TLS certificates are loaded at startup. A Certbot deploy hook should therefore restart the service after a successful renewal.

## TLS and networking

- IPv4 and IPv6 listeners are created for both configured ports.
- HTTPS uses OpenSSL.
- Minimum TLS version is TLS 1.2.
- SNI must match a configured virtual host.
- Wildcard host entries such as `*.example.org` are supported, with exact host entries taking precedence.

## systemd

The repository includes `gmhttpd.service`:

```ini
[Unit]
Description=gmhttpd web server
After=network.target

[Service]
Type=simple
WorkingDirectory=/home/tools/mcp/work/gmhttpd
ExecStart=/home/tools/mcp/work/gmhttpd/gmhttpd server
ExecStop=/home/tools/mcp/work/gmhttpd/gmhttpd stop
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

For another installation, adjust `WorkingDirectory`, `ExecStart` and `ExecStop` if the project is installed elsewhere.

Install and enable it with:

```sh
cp gmhttpd.service /etc/systemd/system/gmhttpd.service
systemctl daemon-reload
systemctl enable --now gmhttpd
```

When systemd is used, use `server` mode rather than `start` so systemd owns the main process directly.

## Runtime files

The server creates these files in its working directory while running:

```text
gmhttpd.pid
gmhttpd.sock
```

`gmhttpd.sock` is the local control socket used by `stats` and `stop`.

## Deployment notes

- Keep private keys readable only by the account running gmhttpd.
- Keep `config` mode `600` when it contains proxy bearer tokens.
- Do not enable new static file extensions unless they are intentionally public.
- Prefer dedicated CGI executables and explicit virtual-host configuration over generic server behavior.
