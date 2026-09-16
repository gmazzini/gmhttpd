// Gianluca Mazzini @2026- Version 1.26

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CONFIG_FILE "config"
#define MAX_HOSTS 64
#define MAX_PROXIES 16
#define MAX_LINE 4096
#define MAX_REQ 16384
#define MAX_BODY 33554432
#define MAX_PATH_LEN 2048
#define CONTROL_SOCKET "gmhttpd.sock"
#define PID_FILE "gmhttpd.pid"

struct vhost {
    char host[256];
    char root[1024];
    char defprog[256];
    char cert[1024];
    char key[1024];
    char redirect[MAX_PATH_LEN];
    SSL_CTX *ctx;
    int catchall;
    int phpcgi;
    int csv;
};

struct proxy_rule {
    char host[256];
    char path[256];
    char addr[64];
    int port;
    char backend_path[256];
    char bearer[256];
};

struct request_info {
    char method[16];
    char path[MAX_PATH_LEN];
    char host[256];
    char content_type[256];
    char cookie[2048];
    char range[256];
    char auth_signature[256];
    char hub_signature[256];
    char sec_purpose[256];
    char user_agent[512];
    char authorization[512];
    long content_length;
    size_t header_length;
};

static struct vhost hosts[MAX_HOSTS];
static struct proxy_rule proxies[MAX_PROXIES];
static int nhosts;
static int nproxies;
static int http_port;
static int https_port;
static char acme_root[1024];
static int pid_fd = -1;

struct server_stats {
    time_t startup;
    unsigned long long connections;
    unsigned long long active;
    unsigned long long requests;
    unsigned long long rejected;
    unsigned long long acme;
    unsigned long long host_requests[MAX_HOSTS];
};

static struct server_stats *stats;

static const char gmhttpd_help[] =
    "gmhttpd 1.26\n"
    "Usage:\n"
    "  ./gmhttpd\n"
    "  ./gmhttpd start\n"
    "  ./gmhttpd server\n"
    "  ./gmhttpd stats\n"
    "  ./gmhttpd stop\n"
    "  ./gmhttpd help\n";

static void usage(void)
{
    fputs(gmhttpd_help, stdout);
}

static void cleanup_files(void)
{
    unlink(CONTROL_SOCKET);
    if (pid_fd >= 0) {
        unlink(PID_FILE);
        close(pid_fd);
        pid_fd = -1;
    }
}

static int lock_pid(void)
{
    char buf[32];
    int len;

    pid_fd = open(PID_FILE, O_RDWR | O_CREAT, 0644);
    if (pid_fd < 0)
        return -1;
    if (flock(pid_fd, LOCK_EX | LOCK_NB) != 0) {
        close(pid_fd);
        pid_fd = -1;
        return -1;
    }
    if (ftruncate(pid_fd, 0) != 0)
        return -1;
    len = snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
    if (len <= 0 || write(pid_fd, buf, (size_t)len) != len)
        return -1;
    return 0;
}

static int make_control_listener(void)
{
    struct sockaddr_un sa;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    if (strlen(CONTROL_SOCKET) >= sizeof(sa.sun_path)) {
        close(fd);
        return -1;
    }
    strcpy(sa.sun_path, CONTROL_SOCKET);
    unlink(CONTROL_SOCKET);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 || listen(fd, 8) < 0) {
        close(fd);
        unlink(CONTROL_SOCKET);
        return -1;
    }
    return fd;
}

static int control_client(const char *command)
{
    struct sockaddr_un sa;
    char buf[4096];
    ssize_t n;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return 1;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strcpy(sa.sun_path, CONTROL_SOCKET);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "gmhttpd is not running\n");
        close(fd);
        return 1;
    }
    if (write(fd, command, strlen(command)) != (ssize_t)strlen(command) || write(fd, "\n", 1) != 1) {
        close(fd);
        return 1;
    }
    for (;;) {
        n = read(fd, buf, sizeof(buf));
        if (n <= 0)
            break;
        if (write(STDOUT_FILENO, buf, (size_t)n) != n) {
            close(fd);
            return 1;
        }
    }
    close(fd);
    return 0;
}

static void format_uptime(char *buf, size_t size, time_t seconds)
{
    unsigned long days;
    unsigned long hours;
    unsigned long minutes;
    unsigned long secs;

    if (seconds < 0)
        seconds = 0;
    days = (unsigned long)(seconds / 86400);
    hours = (unsigned long)((seconds % 86400) / 3600);
    minutes = (unsigned long)((seconds % 3600) / 60);
    secs = (unsigned long)(seconds % 60);
    snprintf(buf, size, "%lud %02lu:%02lu:%02lu", days, hours, minutes, secs);
}

static int control_request(int fd)
{
    char cmd[64];
    char out[4096];
    char uptime[64];
    ssize_t n;
    int i;
    int len;

    n = read(fd, cmd, sizeof(cmd) - 1);
    if (n <= 0)
        return 1;
    cmd[n] = '\0';
    cmd[strcspn(cmd, "\r\n")] = '\0';
    if (strcmp(cmd, "stop") == 0) {
        write(fd, "OK stopping\n", 12);
        return 0;
    }
    if (strcmp(cmd, "stats") != 0) {
        write(fd, "ERR command\n", 12);
        return 1;
    }

    format_uptime(uptime, sizeof(uptime), time(NULL) - stats->startup);
    len = snprintf(out, sizeof(out),
        "gmhttpd 1.26 http=%d https=%d uptime=%s connections=%llu active=%llu requests=%llu rejected=%llu acme=%llu\n",
        http_port, https_port, uptime, stats->connections, stats->active, stats->requests, stats->rejected, stats->acme);
    if (len > 0)
        write(fd, out, (size_t)len);
    for (i = 0; i < nhosts; i++) {
        len = snprintf(out, sizeof(out), "%s %llu\n", hosts[i].host, stats->host_requests[i]);
        if (len > 0)
            write(fd, out, (size_t)len);
    }
    return 1;
}

static int load_proxy_bearer(struct proxy_rule *pr)
{
    FILE *f;
    char value[256];
    size_t n;

    if (pr->bearer[0] != '@')
        return 0;
    f = fopen(pr->bearer + 1, "r");
    if (f == NULL)
        return -1;
    if (fgets(value, sizeof(value), f) == NULL) {
        fclose(f);
        return -1;
    }
    fclose(f);
    n = strcspn(value, "\r\n");
    value[n] = '\0';
    if (n == 0 || n >= sizeof(pr->bearer))
        return -1;
    memcpy(pr->bearer, value, n + 1);
    return 0;
}

static int load_config(const char *name)
{
    FILE *f;
    char line[MAX_LINE];
    char tag[32];
    char mode[32];
    char extra[2];
    struct vhost *h;
    struct proxy_rule *pr;
    int p1;
    int p2;
    int ports_seen;
    int acme_seen;
    int fields;

    f = fopen(name, "r");
    if (f == NULL) {
        perror(name);
        return -1;
    }

    nhosts = 0;
    nproxies = 0;
    http_port = 0;
    https_port = 0;
    acme_root[0] = '\0';
    ports_seen = 0;
    acme_seen = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\0')
            continue;
        if (sscanf(line, "%31s", tag) != 1)
            continue;
        if (strcmp(tag, "ports") == 0) {
            if (ports_seen || sscanf(line, "%31s %d %d", tag, &p1, &p2) != 3 ||
                p1 < 1 || p1 > 65535 || p2 < 1 || p2 > 65535 || p1 == p2) {
                fprintf(stderr, "invalid ports line: %s", line);
                fclose(f);
                return -1;
            }
            http_port = p1;
            https_port = p2;
            ports_seen = 1;
            continue;
        }
        if (strcmp(tag, "acme") == 0) {
            extra[0] = '\0';
            fields = sscanf(line, "%31s %1023s %1s", tag, acme_root, extra);
            if (acme_seen || fields != 2 || acme_root[0] == '\0') {
                fprintf(stderr, "invalid acme line: %s", line);
                fclose(f);
                return -1;
            }
            acme_seen = 1;
            continue;
        }
        if (strcmp(tag, "proxy") == 0) {
            if (nproxies >= MAX_PROXIES) {
                fprintf(stderr, "too many proxy lines\n");
                fclose(f);
                return -1;
            }
            pr = &proxies[nproxies];
            memset(pr, 0, sizeof(*pr));
            extra[0] = '\0';
            fields = sscanf(line, "%31s %255s %255s %63s %d %255s %255s %1s",
                tag, pr->host, pr->path, pr->addr, &pr->port, pr->backend_path, pr->bearer, extra);
            if (fields != 7 || pr->path[0] != '/' || pr->backend_path[0] != '/' ||
                pr->port < 1 || pr->port > 65535 || load_proxy_bearer(pr) != 0) {
                fprintf(stderr, "invalid proxy line: %s", line);
                fclose(f);
                return -1;
            }
            nproxies++;
            continue;
        }
        if (strcmp(tag, "redirect") == 0) {
            if (nhosts >= MAX_HOSTS) {
                fprintf(stderr, "too many host lines\n");
                fclose(f);
                return -1;
            }
            h = &hosts[nhosts];
            memset(h, 0, sizeof(*h));
            extra[0] = '\0';
            fields = sscanf(line, "%31s %255s %2047s %1023s %1023s %1s",
                tag, h->host, h->redirect, h->cert, h->key, extra);
            if (fields != 5 || strncmp(h->redirect, "https://", 8) != 0) {
                fprintf(stderr, "invalid redirect line: %s", line);
                fclose(f);
                return -1;
            }
            nhosts++;
            continue;
        }
        if (strcmp(tag, "host") != 0 || nhosts >= MAX_HOSTS) {
            fprintf(stderr, "invalid config line: %s", line);
            fclose(f);
            return -1;
        }
        h = &hosts[nhosts];
        memset(h, 0, sizeof(*h));
        mode[0] = '\0';
        extra[0] = '\0';
        fields = sscanf(line, "%31s %255s %1023s %255s %1023s %1023s %31s %1s",
            tag, h->host, h->root, h->defprog, h->cert, h->key, mode, extra);
        if (fields != 6 && (fields != 7 || (strcmp(mode, "catchall") != 0 && strcmp(mode, "phpcgi") != 0 && strcmp(mode, "csv") != 0))) {
            fprintf(stderr, "invalid config line: %s", line);
            fclose(f);
            return -1;
        }
        h->catchall = fields == 7 && strcmp(mode, "catchall") == 0;
        h->phpcgi = fields == 7 && strcmp(mode, "phpcgi") == 0;
        h->csv = fields == 7 && strcmp(mode, "csv") == 0;
        nhosts++;
    }
    fclose(f);

    if (!ports_seen) {
        fprintf(stderr, "ports not configured\n");
        return -1;
    }
    if (nhosts == 0) {
        fprintf(stderr, "no hosts configured\n");
        return -1;
    }
    return 0;
}

static int init_tls(void)
{
    int i;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    for (i = 0; i < nhosts; i++) {
        hosts[i].ctx = SSL_CTX_new(TLS_server_method());
        if (hosts[i].ctx == NULL)
            return -1;
        SSL_CTX_set_min_proto_version(hosts[i].ctx, TLS1_2_VERSION);
        if (SSL_CTX_use_certificate_chain_file(hosts[i].ctx, hosts[i].cert) != 1)
            return -1;
        if (SSL_CTX_use_PrivateKey_file(hosts[i].ctx, hosts[i].key, SSL_FILETYPE_PEM) != 1)
            return -1;
        if (SSL_CTX_check_private_key(hosts[i].ctx) != 1)
            return -1;
    }
    return 0;
}

static int find_host(const char *name)
{
    const char *suffix;
    size_t nlen;
    size_t slen;
    int i;

    for (i = 0; i < nhosts; i++) {
        if (strcasecmp(name, hosts[i].host) == 0)
            return i;
    }
    nlen = strlen(name);
    for (i = 0; i < nhosts; i++) {
        if (hosts[i].host[0] != '*' || hosts[i].host[1] != '.')
            continue;
        suffix = hosts[i].host + 1;
        slen = strlen(suffix);
        if (nlen > slen && strcasecmp(name + nlen - slen, suffix) == 0)
            return i;
    }
    return -1;
}

static int sni_cb(SSL *ssl, int *ad, void *arg)
{
    const char *name;
    int n;

    (void)ad;
    (void)arg;
    name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (name == NULL)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    n = find_host(name);
    if (n < 0)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    SSL_set_SSL_CTX(ssl, hosts[n].ctx);
    return SSL_TLSEXT_ERR_OK;
}

static int make_listener(int family, int port)
{
    int fd;
    int one;

    struct sockaddr_in a4;
    struct sockaddr_in6 a6;

    fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (family == AF_INET6) {
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
        memset(&a6, 0, sizeof(a6));
        a6.sin6_family = AF_INET6;
        a6.sin6_addr = in6addr_any;
        a6.sin6_port = htons((unsigned short)port);
        if (bind(fd, (struct sockaddr *)&a6, sizeof(a6)) < 0) {
            close(fd);
            return -1;
        }
    } else {
        memset(&a4, 0, sizeof(a4));
        a4.sin_family = AF_INET;
        a4.sin_addr.s_addr = htonl(INADDR_ANY);
        a4.sin_port = htons((unsigned short)port);
        if (bind(fd, (struct sockaddr *)&a4, sizeof(a4)) < 0) {
            close(fd);
            return -1;
        }
    }

    if (listen(fd, 64) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int read_request(SSL *ssl, char *buf, size_t size)
{
    int n;
    size_t used;

    used = 0;
    while (used + 1 < size) {
        n = SSL_read(ssl, buf + used, (int)(size - used - 1));
        if (n <= 0)
            return -1;
        used += (size_t)n;
        buf[used] = '\0';
        if (strstr(buf, "\r\n\r\n") != NULL)
            return (int)used;
    }
    return -1;
}

static int copy_header_value(char *dst, size_t size, const char *src)
{
    size_t n;

    while (*src == ' ' || *src == '\t')
        src++;
    n = strlen(src);
    if (n == 0 || n >= size)
        return -1;
    memcpy(dst, src, n + 1);
    return 0;
}

static int parse_request(char *req, struct request_info *r)
{
    char *p;
    char *e;
    char *line;
    char *end_headers;
    char *colon;
    char *value;
    char *host_end;
    long length;
    char *endp;
    int seen_length;

    memset(r, 0, sizeof(*r));
    end_headers = strstr(req, "\r\n\r\n");
    if (end_headers == NULL)
        return -1;
    r->header_length = (size_t)(end_headers - req) + 4;

    line = req;
    e = strstr(line, "\r\n");
    if (e == NULL)
        return -1;
    *e = '\0';
    if (sscanf(line, "%15s %2047s HTTP/1.1", r->method, r->path) != 2)
        return -1;
    if (strcmp(r->method, "GET") != 0 && strcmp(r->method, "HEAD") != 0 && strcmp(r->method, "POST") != 0)
        return -2;

    seen_length = 0;
    p = e + 2;
    for (;;) {
        e = strstr(p, "\r\n");
        if (e == NULL)
            return -1;
        if (e == p)
            break;
        *e = '\0';
        colon = strchr(p, ':');
        if (colon == NULL || colon == p)
            return -1;
        *colon = '\0';
        value = colon + 1;

        if (strcasecmp(p, "Host") == 0) {
            if (r->host[0] != '\0' || copy_header_value(r->host, sizeof(r->host), value) < 0)
                return -1;
        } else if (strcasecmp(p, "Content-Length") == 0) {
            while (*value == ' ' || *value == '\t')
                value++;
            if (*value == '\0' || seen_length)
                return -1;
            errno = 0;
            length = strtol(value, &endp, 10);
            if (errno != 0 || *endp != '\0' || length < 0 || length > MAX_BODY)
                return -1;
            r->content_length = length;
            seen_length = 1;
        } else if (strcasecmp(p, "Content-Type") == 0) {
            if (copy_header_value(r->content_type, sizeof(r->content_type), value) < 0)
                return -1;
        } else if (strcasecmp(p, "Cookie") == 0) {
            if (copy_header_value(r->cookie, sizeof(r->cookie), value) < 0)
                return -1;
        } else if (strcasecmp(p, "Range") == 0) {
            if (copy_header_value(r->range, sizeof(r->range), value) < 0)
                return -1;
        } else if (strcasecmp(p, "X-Auth-Signature") == 0) {
            if (copy_header_value(r->auth_signature, sizeof(r->auth_signature), value) < 0)
                return -1;
        } else if (strcasecmp(p, "X-Hub-Signature-256") == 0) {
            if (copy_header_value(r->hub_signature, sizeof(r->hub_signature), value) < 0)
                return -1;
        } else if (strcasecmp(p, "Sec-Purpose") == 0) {
            if (copy_header_value(r->sec_purpose, sizeof(r->sec_purpose), value) < 0)
                return -1;
        } else if (strcasecmp(p, "User-Agent") == 0) {
            if (copy_header_value(r->user_agent, sizeof(r->user_agent), value) < 0)
                return -1;
        } else if (strcasecmp(p, "Authorization") == 0) {
            if (copy_header_value(r->authorization, sizeof(r->authorization), value) < 0)
                return -1;
        } else if (strcasecmp(p, "Transfer-Encoding") == 0) {
            return -3;
        }
        p = e + 2;
    }

    if (r->host[0] == '\0')
        return -1;
    if (r->method[0] == 'P' && !seen_length)
        return -1;
    if (r->host[0] == '[') {
        host_end = strchr(r->host, ']');
        if (host_end == NULL)
            return -1;
        if (host_end[1] != '\0' && host_end[1] != ':')
            return -1;
        *host_end = '\0';
        memmove(r->host, r->host + 1, strlen(r->host));
    } else {
        host_end = strrchr(r->host, ':');
        if (host_end != NULL)
            *host_end = '\0';
    }
    if (r->host[0] == '\0')
        return -1;
    return 0;
}

static void send_simple(SSL *ssl, int code, const char *text);
static int write_all_fd(int fd, const char *buf, size_t size);

static int find_proxy(const char *host, const char *path)
{
    size_t n;
    int i;

    for (i = 0; i < nproxies; i++) {
        if (strcasecmp(host, proxies[i].host) != 0)
            continue;
        n = strlen(proxies[i].path);
        if (strncmp(path, proxies[i].path, n) == 0 &&
            (path[n] == '\0' || path[n] == '?' || path[n] == '/'))
            return i;
    }
    return -1;
}

static int proxy_header_skip(const char *line, size_t n)
{
    const char *colon;
    size_t name_len;

    colon = memchr(line, ':', n);
    if (colon == NULL)
        return 0;
    name_len = (size_t)(colon - line);
    if (name_len == 4 && strncasecmp(line, "Host", 4) == 0)
        return 1;
    if (name_len == 10 && strncasecmp(line, "Connection", 10) == 0)
        return 1;
    if (name_len == 16 && strncasecmp(line, "Proxy-Connection", 16) == 0)
        return 1;
    if (name_len == 10 && strncasecmp(line, "Keep-Alive", 10) == 0)
        return 1;
    return 0;
}

static void run_proxy(SSL *ssl, const struct proxy_rule *pr, const struct request_info *r,
    const char *raw, size_t raw_size)
{
    struct sockaddr_in sa;
    char line[MAX_REQ];
    char target[MAX_PATH_LEN];
    char expected[512];
    char buffer[16384];
    const char *p;
    const char *e;
    const char *suffix;
    const char *body;
    size_t n;
    size_t initial;
    long remaining;
    ssize_t got;
    int fd;
    int len;

    if (snprintf(expected, sizeof(expected), "Bearer %s", pr->bearer) >= (int)sizeof(expected) ||
        strcmp(r->authorization, expected) != 0) {
        send_simple(ssl, 403, "Forbidden");
        return;
    }

    suffix = r->path + strlen(pr->path);
    if (snprintf(target, sizeof(target), "%s%s", pr->backend_path, suffix) >= (int)sizeof(target)) {
        send_simple(ssl, 414, "URI Too Long");
        return;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        send_simple(ssl, 502, "Bad Gateway");
        return;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)pr->port);
    if (inet_pton(AF_INET, pr->addr, &sa.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        send_simple(ssl, 502, "Bad Gateway");
        return;
    }

    len = snprintf(line, sizeof(line), "%s %s HTTP/1.1\r\n", r->method, target);
    if (len <= 0 || write_all_fd(fd, line, (size_t)len) < 0)
        goto done;

    p = strstr(raw, "\r\n");
    if (p == NULL)
        goto done;
    p += 2;
    for (;;) {
        e = strstr(p, "\r\n");
        if (e == NULL)
            goto done;
        if (e == p)
            break;
        n = (size_t)(e - p);
        if (!proxy_header_skip(p, n)) {
            if (write_all_fd(fd, p, n) < 0 || write_all_fd(fd, "\r\n", 2) < 0)
                goto done;
        }
        p = e + 2;
    }
    len = snprintf(line, sizeof(line), "Host: %s:%d\r\nConnection: close\r\n\r\n", pr->addr, pr->port);
    if (len <= 0 || write_all_fd(fd, line, (size_t)len) < 0)
        goto done;

    body = raw + r->header_length;
    initial = raw_size > r->header_length ? raw_size - r->header_length : 0;
    if ((long)initial > r->content_length)
        initial = (size_t)r->content_length;
    if (initial > 0 && write_all_fd(fd, body, initial) < 0)
        goto done;
    remaining = r->content_length - (long)initial;
    while (remaining > 0) {
        size_t want;

        want = remaining > (long)sizeof(buffer) ? sizeof(buffer) : (size_t)remaining;
        got = SSL_read(ssl, buffer, (int)want);
        if (got <= 0 || write_all_fd(fd, buffer, (size_t)got) < 0)
            goto done;
        remaining -= got;
    }

    shutdown(fd, SHUT_WR);
    for (;;) {
        got = read(fd, buffer, sizeof(buffer));
        if (got <= 0)
            break;
        if (SSL_write(ssl, buffer, (int)got) <= 0)
            break;
    }

done:
    close(fd);
}

static int safe_path(const char *path)
{
    if (path[0] != '/')
        return 0;
    if (strstr(path, "..") != NULL)
        return 0;
    if (strchr(path, '\\') != NULL)
        return 0;
    return 1;
}

static void send_simple(SSL *ssl, int code, const char *text)
{
    char buf[512];
    int n;

    n = snprintf(buf, sizeof(buf), "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, text);
    if (n > 0)
        SSL_write(ssl, buf, n);
}

static const char *static_file_type(const char *path, int *attachment, int allow_csv)
{
    const char *ext;

    ext = strrchr(path, '.');
    if (ext == NULL)
        return NULL;
    if (strcasecmp(ext, ".adi") == 0 || strcasecmp(ext, ".cbr") == 0) {
        *attachment = 1;
        return "application/octet-stream";
    }
    if (strcasecmp(ext, ".webp") == 0) {
        *attachment = 0;
        return "image/webp";
    }
    if (strcasecmp(ext, ".html") == 0) {
        *attachment = 0;
        return "text/html; charset=utf-8";
    }
    if (strcasecmp(ext, ".pdf") == 0) {
        *attachment = 0;
        return "application/pdf";
    }
    if (strcasecmp(ext, ".svg") == 0) {
        *attachment = 0;
        return "image/svg+xml";
    }
    if (strcasecmp(ext, ".css") == 0) {
        *attachment = 0;
        return "text/css; charset=utf-8";
    }
    if (strcasecmp(ext, ".js") == 0) {
        *attachment = 0;
        return "application/javascript";
    }
    if (strcasecmp(ext, ".png") == 0) {
        *attachment = 0;
        return "image/png";
    }
    if (strcasecmp(ext, ".jpg") == 0 || strcasecmp(ext, ".jpeg") == 0) {
        *attachment = 0;
        return "image/jpeg";
    }
    if (strcasecmp(ext, ".ogg") == 0) {
        *attachment = 0;
        return "audio/ogg";
    }
    if (strcasecmp(ext, ".gif") == 0) {
        *attachment = 0;
        return "image/gif";
    }
    if (strcasecmp(ext, ".ico") == 0) {
        *attachment = 0;
        return "image/x-icon";
    }
    if (allow_csv && strcasecmp(ext, ".csv") == 0) {
        *attachment = 1;
        return "text/csv; charset=utf-8";
    }
    return NULL;
}

static void send_static(SSL *ssl, const char *path, const char *method, const struct stat *st, const char *type, int attachment)
{
    const char *name;
    char header[1024];
    char buf[16384];
    ssize_t n;
    int fd;
    int len;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        send_simple(ssl, 404, "Not Found");
        return;
    }
    name = strrchr(path, '/');
    name = name == NULL ? path : name + 1;
    if (attachment) {
        len = snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: %s\r\n"
            "Content-Disposition: attachment; filename=\"%s\"\r\n"
            "Content-Length: %lld\r\n"
            "Connection: close\r\n\r\n",
            type, name, (long long)st->st_size);
    } else {
        len = snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %lld\r\n"
            "Connection: close\r\n\r\n",
            type, (long long)st->st_size);
    }
    if (len <= 0 || len >= (int)sizeof(header) || SSL_write(ssl, header, len) <= 0) {
        close(fd);
        return;
    }
    if (strcmp(method, "HEAD") == 0) {
        close(fd);
        return;
    }
    for (;;) {
        n = read(fd, buf, sizeof(buf));
        if (n <= 0)
            break;
        if (SSL_write(ssl, buf, (int)n) <= 0)
            break;
    }
    close(fd);
}

static int write_all_fd(int fd, const char *buf, size_t size)
{
    ssize_t n;
    size_t done;

    done = 0;
    while (done < size) {
        n = write(fd, buf + done, size - done);
        if (n <= 0)
            return -1;
        done += (size_t)n;
    }
    return 0;
}

static int send_cgi_response(SSL *ssl, int fd, int head_only)
{
    char header[MAX_REQ];
    char work[MAX_REQ];
    char out[8192];
    char reason[128];
    char *end;
    char *line;
    char *next;
    char *value;
    size_t header_size;
    size_t used;
    ssize_t n;
    int code;
    int len;

    used = 0;
    for (;;) {
        if (used + 1 >= sizeof(header))
            return -1;
        n = read(fd, header + used, sizeof(header) - used - 1);
        if (n <= 0)
            return -1;
        used += (size_t)n;
        header[used] = '\0';
        end = strstr(header, "\r\n\r\n");
        if (end != NULL)
            break;
    }

    header_size = (size_t)(end - header);
    if (header_size + 1 > sizeof(work))
        return -1;
    memcpy(work, header, header_size);
    work[header_size] = '\0';

    code = 200;
    strcpy(reason, "OK");
    line = work;
    for (;;) {
        next = strstr(line, "\r\n");
        if (next != NULL)
            *next = '\0';
        if (strncasecmp(line, "Status:", 7) == 0) {
            value = line + 7;
            while (*value == ' ' || *value == '\t')
                value++;
            reason[0] = '\0';
            if (sscanf(value, "%d %127[^\r\n]", &code, reason) < 1)
                return -1;
            if (reason[0] == '\0')
                strcpy(reason, "CGI");
        }
        if (next == NULL)
            break;
        line = next + 2;
    }

    len = snprintf(out, sizeof(out), "HTTP/1.1 %d %s\r\nConnection: close\r\n", code, reason);
    if (len <= 0 || SSL_write(ssl, out, len) <= 0)
        return -1;

    memcpy(work, header, header_size);
    work[header_size] = '\0';
    line = work;
    for (;;) {
        next = strstr(line, "\r\n");
        if (next != NULL)
            *next = '\0';
        if (strncasecmp(line, "Status:", 7) != 0 && *line != '\0') {
            if (SSL_write(ssl, line, (int)strlen(line)) <= 0 || SSL_write(ssl, "\r\n", 2) <= 0)
                return -1;
        }
        if (next == NULL)
            break;
        line = next + 2;
    }
    if (SSL_write(ssl, "\r\n", 2) <= 0)
        return -1;

    end = header + header_size + 4;
    if (!head_only && (size_t)(header + used - end) > 0) {
        if (SSL_write(ssl, end, (int)(header + used - end)) <= 0)
            return -1;
    }
    if (head_only)
        return 0;

    for (;;) {
        n = read(fd, out, sizeof(out));
        if (n <= 0)
            break;
        if (SSL_write(ssl, out, (int)n) <= 0)
            return -1;
    }
    return 0;
}

static void run_program(SSL *ssl, struct vhost *h, const struct request_info *r, const char *initial_body, size_t initial_size)
{
    char uri[MAX_PATH_LEN];
    char path[MAX_PATH_LEN];
    char real[MAX_PATH_LEN];
    char length_text[32];
    char script_name[MAX_PATH_LEN];
    char remote_addr[INET6_ADDRSTRLEN];
    char *q;
    const char *query;
    const char *prog;
    const char *ext;
    int inpipe[2];
    int outpipe[2];
    pid_t pid;
    struct stat st;
    struct sockaddr_storage peer;
    socklen_t peerlen;
    char body[8192];
    long remaining;
    ssize_t n;
    int use_php;

    remote_addr[0] = '\0';
    peerlen = sizeof(peer);
    if (getpeername(SSL_get_fd(ssl), (struct sockaddr *)&peer, &peerlen) == 0) {
        if (peer.ss_family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in *)&peer)->sin_addr, remote_addr, sizeof(remote_addr));
        else if (peer.ss_family == AF_INET6)
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&peer)->sin6_addr, remote_addr, sizeof(remote_addr));
    }

    if (strlen(r->path) >= sizeof(uri)) {
        send_simple(ssl, 414, "URI Too Long");
        return;
    }
    strcpy(uri, r->path);
    q = strchr(uri, '?');
    query = "";
    if (q != NULL) {
        *q = '\0';
        query = q + 1;
    }
    if (!safe_path(uri)) {
        send_simple(ssl, 400, "Bad Request");
        return;
    }

    prog = uri;
    if (h->catchall || strcmp(uri, "/") == 0)
        prog = h->defprog;
    else
        prog++;

    if (snprintf(path, sizeof(path), "%s/%s", h->root, prog) >= (int)sizeof(path)) {
        send_simple(ssl, 414, "URI Too Long");
        return;
    }
    if (realpath(path, real) == NULL || stat(real, &st) < 0 || !S_ISREG(st.st_mode)) {
        send_simple(ssl, 404, "Not Found");
        return;
    }
    ext = strrchr(real, '.');
    use_php = h->phpcgi && ext != NULL && strcasecmp(ext, ".php") == 0;
    if (!use_php && access(real, X_OK) != 0) {
        const char *type;
        int attachment;

        attachment = 0;
        type = static_file_type(real, &attachment, h->csv);
        if ((strcmp(r->method, "GET") == 0 || strcmp(r->method, "HEAD") == 0) && type != NULL)
            send_static(ssl, real, r->method, &st, type, attachment);
        else
            send_simple(ssl, 404, "Not Found");
        return;
    }
    if (h->phpcgi && !use_php && access(real, X_OK) == 0) {
        send_simple(ssl, 404, "Not Found");
        return;
    }

    if (pipe(inpipe) < 0) {
        send_simple(ssl, 500, "Internal Server Error");
        return;
    }
    if (pipe(outpipe) < 0) {
        close(inpipe[0]);
        close(inpipe[1]);
        send_simple(ssl, 500, "Internal Server Error");
        return;
    }
    pid = fork();
    if (pid < 0) {
        close(inpipe[0]);
        close(inpipe[1]);
        close(outpipe[0]);
        close(outpipe[1]);
        send_simple(ssl, 500, "Internal Server Error");
        return;
    }
    if (pid == 0) {
        dup2(inpipe[0], STDIN_FILENO);
        dup2(outpipe[1], STDOUT_FILENO);
        close(inpipe[0]);
        close(inpipe[1]);
        close(outpipe[0]);
        close(outpipe[1]);
        setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
        setenv("SERVER_PROTOCOL", "HTTP/1.1", 1);
        setenv("SERVER_SOFTWARE", "gmhttpd/1.26", 1);
        setenv("SERVER_NAME", r->host, 1);
        snprintf(length_text, sizeof(length_text), "%d", https_port);
        setenv("SERVER_PORT", length_text, 1);
        setenv("HTTPS", "on", 1);
        setenv("REQUEST_METHOD", r->method, 1);
        setenv("REQUEST_URI", r->path, 1);
        setenv("QUERY_STRING", query, 1);
        setenv("DOCUMENT_ROOT", h->root, 1);
        if (h->phpcgi && strcmp(uri, "/") == 0)
            snprintf(script_name, sizeof(script_name), "/%s", h->defprog);
        else
            strcpy(script_name, uri);
        setenv("SCRIPT_NAME", script_name, 1);
        setenv("SCRIPT_FILENAME", real, 1);
        setenv("HTTP_HOST", r->host, 1);
        if (remote_addr[0] != '\0')
            setenv("REMOTE_ADDR", remote_addr, 1);
        if (r->user_agent[0] != '\0')
            setenv("HTTP_USER_AGENT", r->user_agent, 1);
        if (use_php)
            setenv("REDIRECT_STATUS", "1", 1);
        if (r->content_type[0] != '\0')
            setenv("CONTENT_TYPE", r->content_type, 1);
        if (r->cookie[0] != '\0')
            setenv("HTTP_COOKIE", r->cookie, 1);
        if (r->range[0] != '\0')
            setenv("HTTP_RANGE", r->range, 1);
        if (r->auth_signature[0] != '\0')
            setenv("HTTP_X_AUTH_SIGNATURE", r->auth_signature, 1);
        if (r->hub_signature[0] != '\0')
            setenv("HTTP_X_HUB_SIGNATURE_256", r->hub_signature, 1);
        if (r->sec_purpose[0] != '\0')
            setenv("HTTP_SEC_PURPOSE", r->sec_purpose, 1);
        if (strcmp(r->method, "POST") == 0) {
            snprintf(length_text, sizeof(length_text), "%ld", r->content_length);
            setenv("CONTENT_LENGTH", length_text, 1);
        }
        if (use_php)
            execl("/usr/bin/php-cgi", "php-cgi", (char *)NULL);
        else
            execl(real, real, (char *)NULL);
        _exit(127);
    }

    close(inpipe[0]);
    close(outpipe[1]);
    remaining = r->content_length;
    if ((long)initial_size > remaining)
        initial_size = (size_t)remaining;
    if (initial_size > 0 && write_all_fd(inpipe[1], initial_body, initial_size) < 0)
        remaining = 0;
    else
        remaining -= (long)initial_size;
    while (remaining > 0) {
        size_t want;

        want = remaining > (long)sizeof(body) ? sizeof(body) : (size_t)remaining;
        n = SSL_read(ssl, body, (int)want);
        if (n <= 0 || write_all_fd(inpipe[1], body, (size_t)n) < 0)
            break;
        remaining -= n;
    }
    close(inpipe[1]);

    if (remaining == 0)
        send_cgi_response(ssl, outpipe[0], strcmp(r->method, "HEAD") == 0);
    else
        send_simple(ssl, 400, "Bad Request");
    close(outpipe[0]);
    waitpid(pid, NULL, 0);
}

static int read_plain_request(int fd, char *buf, size_t size)
{
    ssize_t n;
    size_t used;

    used = 0;
    while (used + 1 < size) {
        n = read(fd, buf + used, size - used - 1);
        if (n <= 0)
            return -1;
        used += (size_t)n;
        buf[used] = '\0';
        if (strstr(buf, "\r\n\r\n") != NULL)
            return (int)used;
    }
    return -1;
}

static void send_plain_simple(int fd, int code, const char *text)
{
    char buf[512];
    int n;

    n = snprintf(buf, sizeof(buf),
        "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        code, text);
    if (n > 0)
        write(fd, buf, (size_t)n);
}

static int send_acme_challenge(int fd, const struct request_info *r)
{
    static const char prefix[] = "/.well-known/acme-challenge/";
    struct stat st;
    char path[MAX_PATH_LEN];
    char header[512];
    char buf[4096];
    const char *token;
    const char *p;
    ssize_t n;
    int file_fd;
    int len;

    if (acme_root[0] == '\0' || strncmp(r->path, prefix, sizeof(prefix) - 1) != 0)
        return 0;
    token = r->path + sizeof(prefix) - 1;
    if (*token == '\0') {
        send_plain_simple(fd, 404, "Not Found");
        return 1;
    }
    for (p = token; *p != '\0'; p++) {
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
            (*p >= '0' && *p <= '9') || *p == '-' || *p == '_')) {
            send_plain_simple(fd, 404, "Not Found");
            return 1;
        }
    }
    if (strcmp(r->method, "GET") != 0 && strcmp(r->method, "HEAD") != 0) {
        send_plain_simple(fd, 405, "Method Not Allowed");
        return 1;
    }
    if (snprintf(path, sizeof(path), "%s/%s", acme_root, token) >= (int)sizeof(path)) {
        send_plain_simple(fd, 404, "Not Found");
        return 1;
    }
    file_fd = open(path, O_RDONLY);
    if (file_fd < 0 || fstat(file_fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        if (file_fd >= 0)
            close(file_fd);
        send_plain_simple(fd, 404, "Not Found");
        return 1;
    }
    len = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %lld\r\nConnection: close\r\n\r\n",
        (long long)st.st_size);
    if (len <= 0 || len >= (int)sizeof(header) || write_all_fd(fd, header, (size_t)len) < 0) {
        close(file_fd);
        return 1;
    }
    if (strcmp(r->method, "HEAD") != 0) {
        for (;;) {
            n = read(file_fd, buf, sizeof(buf));
            if (n <= 0)
                break;
            if (write_all_fd(fd, buf, (size_t)n) < 0)
                break;
        }
    }
    close(file_fd);
    __sync_fetch_and_add(&stats->acme, 1);
    return 1;
}

static void send_target_redirect_plain(int fd, const char *target)
{
    char buf[MAX_PATH_LEN + 128];
    int n;

    n = snprintf(buf, sizeof(buf),
        "HTTP/1.1 308 Permanent Redirect\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        target);
    if (n > 0 && n < (int)sizeof(buf))
        write(fd, buf, (size_t)n);
}

static void send_target_redirect(SSL *ssl, const char *target)
{
    char buf[MAX_PATH_LEN + 128];
    int n;

    n = snprintf(buf, sizeof(buf),
        "HTTP/1.1 308 Permanent Redirect\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        target);
    if (n > 0 && n < (int)sizeof(buf))
        SSL_write(ssl, buf, n);
}

static void send_redirect(int fd, const char *host, const char *path)
{
    char buf[MAX_PATH_LEN + 512];
    int n;

    if (https_port == 443) {
        n = snprintf(buf, sizeof(buf),
            "HTTP/1.1 308 Permanent Redirect\r\nLocation: https://%s%s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            host, path);
    } else {
        n = snprintf(buf, sizeof(buf),
            "HTTP/1.1 308 Permanent Redirect\r\nLocation: https://%s:%d%s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            host, https_port, path);
    }
    if (n > 0 && n < (int)sizeof(buf))
        write(fd, buf, (size_t)n);
}

static void handle_plain_client(int fd)
{
    char req[MAX_REQ];
    struct request_info r;
    int n;
    int rc;
    int hi;

    n = read_plain_request(fd, req, sizeof(req));
    rc = n < 0 ? -1 : parse_request(req, &r);
    if (rc < 0) {
        __sync_fetch_and_add(&stats->rejected, 1);
        send_plain_simple(fd, rc == -2 ? 405 : 400, rc == -2 ? "Method Not Allowed" : "Bad Request");
    } else {
        hi = find_host(r.host);
        if (hi < 0) {
            __sync_fetch_and_add(&stats->rejected, 1);
            send_plain_simple(fd, 421, "Misdirected Request");
        } else if (send_acme_challenge(fd, &r)) {
        } else if (hosts[hi].redirect[0] != '\0')
            send_target_redirect_plain(fd, hosts[hi].redirect);
        else
            send_redirect(fd, r.host, r.path);
    }
    close(fd);
}

static void handle_client(int fd)
{
    SSL *ssl;
    char req[MAX_REQ];
    char raw[MAX_REQ];
    struct request_info r;
    const char *sni;
    const char *body;
    size_t body_size;
    int n;
    int rc;
    int hi;
    int pi;

    ssl = SSL_new(hosts[0].ctx);
    if (ssl == NULL) {
        close(fd);
        return;
    }
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) != 1) {
        __sync_fetch_and_add(&stats->rejected, 1);
        SSL_free(ssl);
        close(fd);
        return;
    }

    n = read_request(ssl, req, sizeof(req));
    if (n > 0) {
        memcpy(raw, req, (size_t)n);
        raw[n] = '\0';
    }
    rc = n < 0 ? -1 : parse_request(req, &r);
    if (rc < 0) {
        __sync_fetch_and_add(&stats->rejected, 1);
        send_simple(ssl, rc == -2 ? 405 : 400, rc == -2 ? "Method Not Allowed" : "Bad Request");
    } else {
        sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        hi = find_host(r.host);
        if (hi < 0 || sni == NULL || strcasecmp(sni, r.host) != 0) {
            __sync_fetch_and_add(&stats->rejected, 1);
            send_simple(ssl, 421, "Misdirected Request");
        } else {
            body = req + r.header_length;
            body_size = (size_t)n > r.header_length ? (size_t)n - r.header_length : 0;
            __sync_fetch_and_add(&stats->requests, 1);
            __sync_fetch_and_add(&stats->host_requests[hi], 1);
            if (hosts[hi].redirect[0] != '\0') {
                send_target_redirect(ssl, hosts[hi].redirect);
            } else {
                pi = find_proxy(r.host, r.path);
                if (pi >= 0)
                    run_proxy(ssl, &proxies[pi], &r, raw, (size_t)n);
                else
                    run_program(ssl, &hosts[hi], &r, body, body_size);
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
}

static void accept_client(int listener, int http4, int http6, int https4, int https6, int ctl, int tls)
{
    pid_t pid;
    int cfd;

    cfd = accept(listener, NULL, NULL);
    if (cfd < 0)
        return;
    __sync_fetch_and_add(&stats->connections, 1);
    __sync_fetch_and_add(&stats->active, 1);
    pid = fork();
    if (pid == 0) {
        if (http4 >= 0)
            close(http4);
        if (http6 >= 0)
            close(http6);
        if (https4 >= 0)
            close(https4);
        if (https6 >= 0)
            close(https6);
        close(ctl);
        if (tls)
            handle_client(cfd);
        else
            handle_plain_client(cfd);
        __sync_fetch_and_sub(&stats->active, 1);
        _exit(0);
    }
    close(cfd);
    if (pid < 0)
        __sync_fetch_and_sub(&stats->active, 1);
}

static int run_server(int daemon_mode, int ready_fd)
{
    fd_set rfds;
    int http4;
    int http6;
    int https4;
    int https6;
    int ctl;
    int cfd;
    int maxfd;
    int running;

    if (lock_pid() != 0) {
        fprintf(stderr, "gmhttpd already running or pid file unavailable.\n");
        return 1;
    }
    atexit(cleanup_files);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    if (load_config(CONFIG_FILE) < 0)
        return 1;
    if (init_tls() < 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    SSL_CTX_set_tlsext_servername_callback(hosts[0].ctx, sni_cb);

    stats = mmap(NULL, sizeof(*stats), PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (stats == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memset(stats, 0, sizeof(*stats));
    stats->startup = time(NULL);

    http4 = make_listener(AF_INET, http_port);
    http6 = make_listener(AF_INET6, http_port);
    https4 = make_listener(AF_INET, https_port);
    https6 = make_listener(AF_INET6, https_port);
    if ((http4 < 0 && http6 < 0) || (https4 < 0 && https6 < 0)) {
        perror("listen");
        return 1;
    }
    ctl = make_control_listener();
    if (ctl < 0) {
        perror("control socket");
        return 1;
    }

    if (daemon_mode) {
        char ready;
        int nullfd;

        ready = '1';
        if (write(ready_fd, &ready, 1) != 1)
            return 1;
        close(ready_fd);
        nullfd = open("/dev/null", O_RDWR);
        if (nullfd >= 0) {
            dup2(nullfd, STDIN_FILENO);
            dup2(nullfd, STDOUT_FILENO);
            dup2(nullfd, STDERR_FILENO);
            if (nullfd > STDERR_FILENO)
                close(nullfd);
        }
    }

    running = 1;
    while (running) {
        FD_ZERO(&rfds);
        maxfd = ctl;
        FD_SET(ctl, &rfds);
        if (http4 >= 0) {
            FD_SET(http4, &rfds);
            if (http4 > maxfd)
                maxfd = http4;
        }
        if (http6 >= 0) {
            FD_SET(http6, &rfds);
            if (http6 > maxfd)
                maxfd = http6;
        }
        if (https4 >= 0) {
            FD_SET(https4, &rfds);
            if (https4 > maxfd)
                maxfd = https4;
        }
        if (https6 >= 0) {
            FD_SET(https6, &rfds);
            if (https6 > maxfd)
                maxfd = https6;
        }
        if (select(maxfd + 1, &rfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (FD_ISSET(ctl, &rfds)) {
            cfd = accept(ctl, NULL, NULL);
            if (cfd >= 0) {
                running = control_request(cfd);
                close(cfd);
            }
        }
        if (running && http4 >= 0 && FD_ISSET(http4, &rfds))
            accept_client(http4, http4, http6, https4, https6, ctl, 0);
        if (running && http6 >= 0 && FD_ISSET(http6, &rfds))
            accept_client(http6, http4, http6, https4, https6, ctl, 0);
        if (running && https4 >= 0 && FD_ISSET(https4, &rfds))
            accept_client(https4, http4, http6, https4, https6, ctl, 1);
        if (running && https6 >= 0 && FD_ISSET(https6, &rfds))
            accept_client(https6, http4, http6, https4, https6, ctl, 1);
    }

    close(ctl);
    if (http4 >= 0)
        close(http4);
    if (http6 >= 0)
        close(http6);
    if (https4 >= 0)
        close(https4);
    if (https6 >= 0)
        close(https6);
    munmap(stats, sizeof(*stats));
    return 0;
}

static int start_server(void)
{
    int pfd[2];
    pid_t pid;
    char ready;
    ssize_t n;

    if (pipe(pfd) != 0) {
        perror("pipe");
        return 1;
    }
    pid = fork();
    if (pid < 0) {
        perror("fork");
        close(pfd[0]);
        close(pfd[1]);
        return 1;
    }
    if (pid > 0) {
        close(pfd[1]);
        do {
            n = read(pfd[0], &ready, 1);
        } while (n < 0 && errno == EINTR);
        close(pfd[0]);
        if (n == 1 && ready == '1') {
            printf("gmhttpd 1.23 is running\n");
            return 0;
        }
        waitpid(pid, NULL, 0);
        return 1;
    }

    close(pfd[0]);
    if (setsid() < 0) {
        perror("setsid");
        close(pfd[1]);
        _exit(1);
    }
    return run_server(1, pfd[1]);
}

int main(int argc, char **argv)
{
    if (argc == 1) {
        usage();
        return 0;
    }
    if (argc != 2) {
        usage();
        return 1;
    }
    if (strcmp(argv[1], "help") == 0) {
        usage();
        return 0;
    }
    if (strcmp(argv[1], "start") == 0)
        return start_server();
    if (strcmp(argv[1], "server") == 0)
        return run_server(0, -1);
    if (strcmp(argv[1], "stats") == 0 || strcmp(argv[1], "stop") == 0)
        return control_client(argv[1]);
    usage();
    return 1;
}
