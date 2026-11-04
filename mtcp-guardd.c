/*
 * mtcp-guardd — userspace daemon for cve_2026_98432 XDP guard.
 *
 * Consumes drop events from the eBPF perf event array map, logs each
 * drop via journald, and supports SIGHUP-driven config reload.
 *
 * All logging goes through systemd-journald via sd_journal_*(). This
 * works without /dev/log and without rsyslog: journald captures the
 * messages directly, and `journalctl -u mtcp-guardd` shows them.
 *
 * Event-driven: uses libbpf perf buffer (epoll-backed), no busy polling.
 */

#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <systemd/sd-journal.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>

#ifndef __u32
#define __u32 uint32_t
#endif
#ifndef __u64
#define __u64 uint64_t
#endif

#define EVENTS_PIN        "/sys/fs/bpf/cve_2026_98432_events"
#define CONFIG_PIN        "/sys/fs/bpf/cve_2026_98432_config"
#define WHITELIST_PIN     "/sys/fs/bpf/cve_2026_98432_whitelist"
#define WHITELIST_BM_PIN  "/sys/fs/bpf/cve_2026_98432_whitelist_bm"
#define WHITELIST_CONF    "/etc/cve-2026-98432-guard/whitelist.conf"
#define PID_FILE          "/run/mtcp-guardd.pid"

#ifndef BPF_NOEXIST
#define BPF_NOEXIST 1
#define BPF_EXIST   2
#endif

struct drop_event {
    __u32 src_ip;
    __u64 count;
};

/* Prefix mask, mirroring prefix24() in cve_2026_98432_guard.c. */
static inline __u32 prefix24(__u32 ip)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ip & 0x00ffffffU;
#else
    return ip & 0xffffff00U;
#endif
}

static volatile sig_atomic_t g_reload = 0;
static volatile sig_atomic_t g_stop   = 0;

static void handle_sighup(int sig)
{
    (void)sig;
    g_reload = 1;
}

static void handle_stop(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* Format an IP into a caller-supplied buffer. Never returns NULL. */
static const char *fmt_ip(__u32 ip, char *buf, size_t buflen)
{
    struct in_addr in;
    in.s_addr = ip;
    if (!inet_ntop(AF_INET, &in, buf, buflen)) {
        snprintf(buf, buflen, "<?>");
    }
    return buf;
}

/* Read the current wake flag from the config map. */
static int read_wake_flag(__u32 *out)
{
    int fd = bpf_obj_get(CONFIG_PIN);
    if (fd < 0) {
        sd_journal_print(LOG_ERR,
            "config: cannot open %s: %s", CONFIG_PIN, strerror(errno));
        return -1;
    }
    __u32 key = 0, val = 0;
    int rc = bpf_map_lookup_elem(fd, &key, &val);
    int saved_errno = errno;
    close(fd);
    if (rc < 0) {
        sd_journal_print(LOG_ERR,
            "config: cannot read key 0: %s", strerror(saved_errno));
        return -1;
    }
    *out = val;
    return 0;
}

/*
 * Load the persistent whitelist file into the BPF maps.
 *
 * Correct semantics for the current map schema:
 *   - exact IP   -> cve_2026_98432_whitelist,    key = raw saddr, value = u8 1
 *   - /24 prefix -> cve_2026_98432_whitelist_bm, key = prefix24(saddr), value = u8 1
 *
 * `no_clear` = 0 means: reset the maps first, so a SIGHUP with a smaller
 * file actually removes the entries that were previously loaded.
 */
static int load_whitelist_file(int no_clear)
{
    FILE *f = fopen(WHITELIST_CONF, "r");
    if (!f) {
        sd_journal_print(LOG_WARNING,
            "whitelist: cannot open %s: %s",
            WHITELIST_CONF, strerror(errno));
        return -1;
    }

    int wl_fd = bpf_obj_get(WHITELIST_PIN);
    if (wl_fd < 0) {
        sd_journal_print(LOG_ERR,
            "whitelist: cannot open %s: %s",
            WHITELIST_PIN, strerror(errno));
        fclose(f);
        return -1;
    }
    int bm_fd = bpf_obj_get(WHITELIST_BM_PIN);
    if (bm_fd < 0) {
        sd_journal_print(LOG_ERR,
            "whitelist: cannot open %s: %s",
            WHITELIST_BM_PIN, strerror(errno));
        close(wl_fd);
        fclose(f);
        return -1;
    }

    /* Optionally clear both maps before loading. */
    if (!no_clear) {
        __u32 prev = 0, cur;
        while (bpf_map_get_next_key(wl_fd, &prev, &cur) == 0) {
            bpf_map_delete_elem(wl_fd, &cur);
            prev = cur;
        }
        prev = 0;
        while (bpf_map_get_next_key(bm_fd, &prev, &cur) == 0) {
            bpf_map_delete_elem(bm_fd, &cur);
            prev = cur;
        }
    }

    char line[256];
    int lineno = 0, added = 0, errors = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#')
            continue;

        char *slash = strchr(p, '/');
        int is_prefix = 0;
        if (slash) {
            *slash = '\0';
            if (strcmp(slash + 1, "24") != 0) {
                sd_journal_print(LOG_WARNING,
                    "whitelist: %s:%d: only /24 supported, skipping '%s/%s'",
                    WHITELIST_CONF, lineno, p, slash + 1);
                errors++;
                continue;
            }
            is_prefix = 1;
        }

        struct in_addr in;
        if (inet_pton(AF_INET, p, &in) != 1) {
            sd_journal_print(LOG_WARNING,
                "whitelist: %s:%d: invalid IP '%s'",
                WHITELIST_CONF, lineno, p);
            errors++;
            continue;
        }

        __u32 ip;
        memcpy(&ip, &in.s_addr, sizeof(ip));
        __u8 val = 1;

        int rc;
        if (is_prefix) {
            __u32 key = prefix24(ip);
            rc = bpf_map_update_elem(bm_fd, &key, &val, BPF_ANY);
        } else {
            rc = bpf_map_update_elem(wl_fd, &ip, &val, BPF_ANY);
        }
        if (rc) {
            char ipbuf[INET_ADDRSTRLEN];
            fmt_ip(ip, ipbuf, sizeof(ipbuf));
            sd_journal_print(LOG_WARNING,
                "whitelist: %s:%d: update failed for %s%s: %s",
                WHITELIST_CONF, lineno, ipbuf,
                is_prefix ? "/24" : "", strerror(errno));
            errors++;
            continue;
        }
        added++;
    }

    fclose(f);
    close(wl_fd);
    close(bm_fd);
    sd_journal_print(LOG_INFO,
        "whitelist: reload from %s: %d added, %d error(s)",
        WHITELIST_CONF, added, errors);
    return errors ? -1 : 0;
}

static void reload_config(void)
{
    __u32 wake = 0;
    if (read_wake_flag(&wake) == 0) {
        sd_journal_print(LOG_INFO, "config reload: wake=%u", wake);
    }
    /* Reload clears the maps, so SIGHUP semantics are "current file wins". */
    load_whitelist_file(0);
}

/*
 * Rate-limit repeated drops from the same source.
 *
 * The BPF program updates the per-source counter on every dropped
 * packet. Logging every drop would flood journald at line rate during
 * an attack. Instead we log the first drop per source and then only
 * every Nth subsequent drop (N = DROP_LOG_INTERVAL) per source. This
 * keeps the log useful while surviving a flood.
 */
#define DROP_LOG_INTERVAL 100

static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    (void)ctx; (void)cpu;

    if (size < sizeof(struct drop_event))
        return;

    struct drop_event *ev = data;
    char ipbuf[INET_ADDRSTRLEN];
    fmt_ip(ev->src_ip, ipbuf, sizeof(ipbuf));

    /*
     * Log every drop. No rate limiting: the operator wants the full
     * attack picture in journald. If the volume becomes a problem,
     * tune journald (RateLimitIntervalSec/RateLimitBurst in
     * journald.conf) or add a periodic summary instead of per-event
     * suppression here.
     */
    sd_journal_print(LOG_WARNING,
        "drop src_ip=%s source_total=%llu",
        ipbuf, (unsigned long long)ev->count);
}

static int write_pid_file(void)
{
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%s.XXXXXX", PID_FILE);
    int fd = mkstemp(tmp);
    if (fd < 0) {
        sd_journal_print(LOG_ERR,
            "pid: cannot create temp file for %s: %s",
            PID_FILE, strerror(errno));
        return -1;
    }
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
    if (write(fd, buf, n) != n) {
        sd_journal_print(LOG_ERR,
            "pid: short write to %s: %s", PID_FILE, strerror(errno));
        close(fd);
        unlink(tmp);
        return -1;
    }
    close(fd);
    if (rename(tmp, PID_FILE) != 0) {
        sd_journal_print(LOG_ERR,
            "pid: rename %s -> %s: %s", tmp, PID_FILE, strerror(errno));
        unlink(tmp);
        return -1;
    }
    return 0;
}

static void remove_pid_file(void)
{
    if (unlink(PID_FILE) != 0 && errno != ENOENT) {
        sd_journal_print(LOG_WARNING,
            "pid: cannot remove %s: %s", PID_FILE, strerror(errno));
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [-d] [-h]\n"
        "\n"
        "  -d         daemonize (background, detach from tty)\n"
        "  -h, --help show this help\n"
        "\n"
        "Logs go to journald. Inspect with:\n"
        "  journalctl -u mtcp-guardd -f\n",
        prog);
}

int main(int argc, char **argv)
{
    struct perf_buffer *pb = NULL;
    int events_fd;
    int c;
    int daemonize = 0;

    while ((c = getopt(argc, argv, "dh")) != -1) {
        switch (c) {
        case 'd':
            daemonize = 1;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /*
     * Daemonize before opening any BPF or file resources, so file
     * descriptors aren't duplicated across the fork and the child
     * has a clean state.
     */
    if (daemonize) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            return 1;
        }
        if (pid > 0)
            _exit(0);
        if (setsid() < 0) {
            /* After fork+setsid fails, there's no reasonable recovery;
             * journald still gets the error if /dev/log is reachable. */
            sd_journal_print(LOG_ERR, "daemonize: setsid: %s", strerror(errno));
            return 1;
        }
        umask(0);
        if (chdir("/") != 0) {
            sd_journal_print(LOG_WARNING,
                "daemonize: chdir(/): %s", strerror(errno));
            /* Non-fatal. */
        }
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    sd_journal_print(LOG_INFO,
        "mtcp-guardd starting (pid=%d, daemonized=%d)",
        (int)getpid(), daemonize);

    if (write_pid_file() != 0) {
        /* Non-fatal: the daemon can still serve, but log loudly. */
        sd_journal_print(LOG_WARNING,
            "continuing without pid file; 'remove' may not find the pid");
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sighup;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGHUP, &sa, NULL) != 0) {
        sd_journal_print(LOG_ERR,
            "sigaction(SIGHUP): %s", strerror(errno));
        remove_pid_file();
        return 1;
    }
    sa.sa_handler = handle_stop;
    if (sigaction(SIGTERM, &sa, NULL) != 0 ||
        sigaction(SIGINT,  &sa, NULL) != 0) {
        sd_journal_print(LOG_ERR,
            "sigaction(SIGTERM/SIGINT): %s", strerror(errno));
        remove_pid_file();
        return 1;
    }

    events_fd = bpf_obj_get(EVENTS_PIN);
    if (events_fd < 0) {
        sd_journal_print(LOG_ERR,
            "events: cannot open %s: %s\n"
            "  hint: is the guard loaded and pinned? check:\n"
            "    sudo bpftool prog show\n"
            "    sudo ls -la /sys/fs/bpf/",
            EVENTS_PIN, strerror(errno));
        remove_pid_file();
        return 1;
    }

    /*
     * perf_buffer_opts signature varies across libbpf versions. Modern
     * libbpf (>= 0.6) uses perf_buffer__new(fd, opts) and lets the opts
     * struct carry the page count; older libbpf uses perf_buffer__new(fd,
     * page_cnt, opts). We detect via __has_include is not possible here,
     * so use the modern signature and rely on a recent libbpf; the
     * build script already checks for libbpf via pkg-config.
     */
    struct perf_buffer_opts pb_opts = {
        .sample_cb = handle_event,
        .lost_cb   = NULL,
        .ctx       = NULL,
    };
    pb = perf_buffer__new(events_fd, 8, &pb_opts);
    if (!pb) {
        sd_journal_print(LOG_ERR,
            "perf_buffer: cannot create buffer: %s", strerror(errno));
        close(events_fd);
        remove_pid_file();
        return 1;
    }

    /* Initial config read + whitelist load. */
    reload_config();

    sd_journal_print(LOG_INFO, "mtcp-guardd ready");

    while (!g_stop) {
        int err = perf_buffer__poll(pb, 1000 /* ms */);
        if (err < 0 && err != -EINTR) {
            sd_journal_print(LOG_WARNING,
                "perf_buffer_poll: %s", strerror(-err));
        }

        if (g_reload) {
            g_reload = 0;
            sd_journal_print(LOG_INFO, "received SIGHUP, reloading");
            reload_config();
        }
    }

    sd_journal_print(LOG_INFO, "mtcp-guardd shutting down");
    perf_buffer__free(pb);
    close(events_fd);
    remove_pid_file();
    return 0;
}
