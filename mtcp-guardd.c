/*
 * mtcp-guardd — userspace daemon for cve_2026_98432 XDP guard.
 *
 * Consumes drop events from the eBPF perf event array map, logs each
 * drop via syslog, and supports SIGHUP-driven config reload.
 *
 * Event-driven: uses libbpf perf buffer (epoll-backed), no busy polling.
 */

#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
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

#define EVENTS_PIN "/sys/fs/bpf/cve_2026_98432_events"
#define CONFIG_PIN "/sys/fs/bpf/cve_2026_98432_config"
#define WHITELIST_PIN "/sys/fs/bpf/cve_2026_98432_whitelist"
#define WHITELIST_BM_PIN "/sys/fs/bpf/cve_2026_98432_whitelist_bm"
#define WHITELIST_CONF "/etc/cve-2026_98432_guard/whitelist.conf"
#define PID_FILE   "/run/mtcp-guardd.pid"

#ifndef BPF_NOEXIST
#define BPF_NOEXIST 1
#define BPF_EXIST   2
#endif

struct drop_event {
    __u32 src_ip;
    __u64 count;
};

static void load_whitelist_file(void);

static __u32 ntoh32(__u32 v)
{
    return __builtin_bswap32(v);
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

static void reload_config(void)
{
    int fd;
    __u32 key = 0;
    __u32 val = 0;

    fd = bpf_obj_get(CONFIG_PIN);
    if (fd < 0) {
        syslog(LOG_WARNING, "cannot open config map: %s", strerror(errno));
        return;
    }

    if (bpf_map_lookup_elem(fd, &key, &val) < 0) {
        syslog(LOG_WARNING, "cannot read config map: %s", strerror(errno));
        close(fd);
        return;
    }
    close(fd);

    syslog(LOG_INFO, "config reload: wake=%u", val);

    /* Also (re)load whitelist from persistent file */
    load_whitelist_file();
}

static void load_whitelist_file(void)
{
    FILE *f = fopen(WHITELIST_CONF, "r");
    if (!f) {
        syslog(LOG_WARNING, "cannot open whitelist conf %s: %s",
               WHITELIST_CONF, strerror(errno));
        return;
    }

    char line[256];
    int loaded = 0;

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        if (len == 0 || line[0] == '#')
            continue;

        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#')
            continue;

        char *slash = strchr(p, '/');
        int is_bm = 0;
        __u32 ip = 0;

        if (slash) {
            *slash = '\0';
            if (strcmp(slash + 1, "24") != 0)
                continue; /* only /24 supported */
            is_bm = 1;
        }

        if (inet_pton(AF_INET, p, &ip) != 1) {
            syslog(LOG_WARNING, "invalid IP in whitelist conf: %s", p);
            continue;
        }
        ip = ntoh32(ip);

        int fd = is_bm ? bpf_obj_get(WHITELIST_BM_PIN) : bpf_obj_get(WHITELIST_PIN);
        if (fd < 0) {
            syslog(LOG_WARNING, "cannot open whitelist map: %s", strerror(errno));
            fclose(f);
            return;
        }

        if (is_bm) {
            __u32 idx = ip >> 8;
            __u32 bit = 1 << ((ip >> 3) & 0x1f);
            __u32 cur = 0;
            if (bpf_map_lookup_elem(fd, &idx, &cur) < 0)
                cur = 0;
            cur |= bit;
            if (bpf_map_update_elem(fd, &idx, &cur, BPF_EXIST) < 0 &&
                bpf_map_update_elem(fd, &idx, &cur, BPF_NOEXIST) < 0) {
                syslog(LOG_WARNING, "failed to update bitmap for %s: %s", p, strerror(errno));
            } else {
                loaded++;
            }
        } else {
            __u8 val = 1;
            if (bpf_map_update_elem(fd, &ip, &val, BPF_NOEXIST) < 0 &&
                bpf_map_update_elem(fd, &ip, &val, BPF_EXIST) < 0) {
                syslog(LOG_WARNING, "failed to update whitelist for %s: %s", p, strerror(errno));
            } else {
                loaded++;
            }
        }

        close(fd);
    }

    fclose(f);
    syslog(LOG_INFO, "whitelist reload: %d entries loaded from %s", loaded, WHITELIST_CONF);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    struct drop_event *ev;
    char ip[INET_ADDRSTRLEN];
    struct in_addr in;

    (void)ctx;
    (void)cpu;

    if (size < sizeof(*ev))
        return;

    ev = data;
    in.s_addr = ev->src_ip;
    inet_ntop(AF_INET, &in, ip, sizeof(ip));

    syslog(LOG_INFO, "drop src_ip=%s count=%llu", ip, (unsigned long long)ev->count);
}

static void write_pid_file(void)
{
    FILE *f = fopen(PID_FILE, "w");
    if (f) {
        fprintf(f, "%d\n", (int)getpid());
        fclose(f);
    }
}

static void remove_pid_file(void)
{
    unlink(PID_FILE);
}

int main(int argc, char **argv)
{
    struct perf_buffer *pb = NULL;
    int events_fd;
    int c;
    int daemonize = 0;

    while ((c = getopt(argc, argv, "d")) != -1) {
        switch (c) {
        case 'd':
            daemonize = 1;
            break;
        default:
            fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
            return 1;
        }
    }

    if (daemonize) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            return 1;
        }
        if (pid > 0)
            _exit(0);
        setsid();
        umask(0);
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    write_pid_file();

    openlog("mtcp-guardd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    syslog(LOG_INFO, "mtcp-guardd starting");

    signal(SIGHUP, handle_sighup);
    signal(SIGTERM, handle_stop);
    signal(SIGINT,  handle_stop);

    events_fd = bpf_obj_get(EVENTS_PIN);
    if (events_fd < 0) {
        syslog(LOG_ERR, "cannot open events map: %s", strerror(errno));
        remove_pid_file();
        closelog();
        return 1;
    }

    struct perf_buffer_opts pb_opts = {
        .sample_cb = handle_event,
        .lost_cb   = NULL,
        .ctx       = NULL,
    };
    pb = perf_buffer__new(events_fd, 8, &pb_opts);
    if (!pb) {
        syslog(LOG_ERR, "cannot create perf buffer");
        close(events_fd);
        remove_pid_file();
        closelog();
        return 1;
    }

    /* Initial config read */
    reload_config();

    while (!g_stop) {
        int err = perf_buffer__poll(pb, 1000 /* ms */);
        if (err < 0 && err != -EINTR) {
            syslog(LOG_WARNING, "perf_buffer_poll: %s", strerror(-err));
        }

        if (g_reload) {
            g_reload = 0;
            reload_config();
        }
    }

    perf_buffer__free(pb);
    close(events_fd);
    remove_pid_file();
    closelog();
    syslog(LOG_INFO, "mtcp-guardd stopping");
    return 0;
}
