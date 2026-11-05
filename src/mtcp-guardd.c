
/*
 * mtcp-guardd — userspace daemon for cve_2026_98432 XDP guard.
 *
 * Consumes:
 *
 *   [struct meta_event (8 bytes)][caplen bytes of raw frame]
 *
 * from the perf event map.
 *
 * Event magic:
 *
 *   META_MAGIC          Enforce: packet dropped
 *   META_MAGIC_MONITOR  Monitor: packet allowed
 *
 * Configuration map:
 *
 *   key 0: wake
 *   key 1: mode
 *
 *   mode 0 = enforce
 *   mode 1 = monitor
 *
 * Logs detected packets to journald (or syslog fallback).
 * Optionally writes dropped packet bytes to a PCAP file.
 */

#define _GNU_SOURCE

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <linux/types.h>

#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>

#if defined(__has_include)
#  if __has_include(<systemd/sd-journal.h>)
#    include <systemd/sd-journal.h>
#    define HAVE_SD_JOURNAL 1
#  endif
#endif

#ifdef HAVE_SD_JOURNAL
#  define LOG_JOURNAL(prio, fmt, ...) \
       sd_journal_print((prio), (fmt), ##__VA_ARGS__)
#else
#  define LOG_JOURNAL(prio, fmt, ...) \
       syslog((prio), (fmt), ##__VA_ARGS__)
#endif

#ifdef HAVE_PCAP
#  include "pcap_writer.h"
static pcap_writer_t *g_pcap = NULL;
static unsigned long long g_pcap_written = 0;
#endif

/* ------------------------------------------------------------
 * Pinned BPF maps
 * ------------------------------------------------------------ */

#define EVENTS_PIN        "/sys/fs/bpf/cve_2026_98432_events"
#define CONFIG_PIN        "/sys/fs/bpf/cve_2026_98432_config"
#define WHITELIST_PIN     "/sys/fs/bpf/cve_2026_98432_whitelist"
#define WHITELIST_BM_PIN  "/sys/fs/bpf/cve_2026_98432_whitelist_bm"

#define WHITELIST_CONF    "/etc/cve-2026-98432-guard/whitelist.conf"
#define PID_FILE          "/run/mtcp-guardd.pid"

/* ------------------------------------------------------------
 * Event and configuration definitions
 * ------------------------------------------------------------ */

#define MAX_CAPTURE                 9216
#define PERF_BUFFER_PAGES_PER_CPU   64

#define META_MAGIC          0x5043544DU
#define META_MAGIC_MONITOR  0xD043544DU

#define CONFIG_KEY_WAKE     0
#define CONFIG_KEY_MODE     1

#define GUARD_MODE_ENFORCE  0
#define GUARD_MODE_MONITOR  1

#ifndef BPF_NOEXIST
#define BPF_NOEXIST 1
#define BPF_EXIST   2
#endif

struct meta_event {
    __u32 magic;
    __u32 ifindex;
};

/* ------------------------------------------------------------
 * Source counters
 * ------------------------------------------------------------ */

#define MAX_CPUS 256

static __u32 g_count_ip[MAX_CPUS];
static __u64 g_count_val[MAX_CPUS];
static unsigned g_count_slot = 0;

static __u64 bump_source_count(__u32 ip)
{
    for (unsigned i = 0; i < MAX_CPUS; i++) {
        if (g_count_ip[i] == ip && g_count_val[i] > 0) {
            g_count_val[i]++;
            return g_count_val[i];
        }
    }

    g_count_ip[g_count_slot] = ip;
    g_count_val[g_count_slot] = 1;

    g_count_slot = (g_count_slot + 1) % MAX_CPUS;

    return 1;
}

/*
 * Convert IPv4 address to its /24 network key.
 * Address representation matches the BPF map key.
 */

static inline __u32 prefix24(__u32 ip)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ip & 0x00ffffffU;
#else
    return ip & 0xffffff00U;
#endif
}

/* ------------------------------------------------------------
 * Signals
 * ------------------------------------------------------------ */

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

/* ------------------------------------------------------------
 * IPv4 formatting
 * ------------------------------------------------------------ */

static const char *fmt_ip(__u32 ip, char *buf, size_t buflen)
{
    struct in_addr in;

    in.s_addr = ip;

    if (!inet_ntop(AF_INET, &in, buf, buflen))
        snprintf(buf, buflen, "<?>");

    return buf;
}

/* ------------------------------------------------------------
 * Read BPF configuration
 *
 * key 0 = wake
 * key 1 = mode
 * ------------------------------------------------------------ */

static int read_config(__u32 *wake, __u32 *mode)
{
    int fd = bpf_obj_get(CONFIG_PIN);

    if (fd < 0) {
        LOG_JOURNAL(LOG_ERR,
            "config: cannot open %s: %s",
            CONFIG_PIN, strerror(errno));
        return -1;
    }

    __u32 key = CONFIG_KEY_WAKE;
    __u32 val = 0;

    if (bpf_map_lookup_elem(fd, &key, &val) < 0) {
        int saved_errno = errno;

        close(fd);

        LOG_JOURNAL(LOG_ERR,
            "config: cannot read wake key: %s",
            strerror(saved_errno));

        return -1;
    }

    *wake = val;

    key = CONFIG_KEY_MODE;
    val = GUARD_MODE_ENFORCE;

    if (bpf_map_lookup_elem(fd, &key, &val) < 0) {
        LOG_JOURNAL(LOG_WARNING,
            "config: cannot read mode key, defaulting to enforce: %s",
            strerror(errno));

        val = GUARD_MODE_ENFORCE;
    }

    close(fd);

    if (val != GUARD_MODE_ENFORCE &&
        val != GUARD_MODE_MONITOR) {

        LOG_JOURNAL(LOG_WARNING,
            "config: invalid mode=%u, defaulting to enforce",
            val);

        val = GUARD_MODE_ENFORCE;
    }

    *mode = val;

    return 0;
}

/* ------------------------------------------------------------
 * Whitelist loader
 * ------------------------------------------------------------ */

static int load_whitelist_file(int no_clear)
{
    FILE *f = fopen(WHITELIST_CONF, "r");

    if (!f) {
        LOG_JOURNAL(LOG_WARNING,
            "whitelist: cannot open %s: %s",
            WHITELIST_CONF, strerror(errno));

        return -1;
    }

    int wl_fd = bpf_obj_get(WHITELIST_PIN);

    if (wl_fd < 0) {
        LOG_JOURNAL(LOG_ERR,
            "whitelist: cannot open %s: %s",
            WHITELIST_PIN, strerror(errno));

        fclose(f);
        return -1;
    }

    int bm_fd = bpf_obj_get(WHITELIST_BM_PIN);

    if (bm_fd < 0) {
        LOG_JOURNAL(LOG_ERR,
            "whitelist: cannot open %s: %s",
            WHITELIST_BM_PIN, strerror(errno));

        close(wl_fd);
        fclose(f);

        return -1;
    }

    if (!no_clear) {
        __u32 prev = 0;
        __u32 cur;

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

    int lineno = 0;
    int added = 0;
    int errors = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;

        size_t len = strlen(line);

        while (len > 0 &&
               (line[len - 1] == '\n' ||
                line[len - 1] == '\r')) {
            line[--len] = '\0';
        }

        char *p = line;

        while (*p == ' ' || *p == '\t')
            p++;

        if (*p == '\0' || *p == '#')
            continue;

        char *slash = strchr(p, '/');

        int is_prefix = 0;

        if (slash) {
            *slash = '\0';

            if (strcmp(slash + 1, "24") != 0) {
                LOG_JOURNAL(LOG_WARNING,
                    "whitelist: %s:%d: only /24 supported, skipping '%s/%s'",
                    WHITELIST_CONF, lineno, p, slash + 1);

                errors++;
                continue;
            }

            is_prefix = 1;
        }

        struct in_addr in;

        if (inet_pton(AF_INET, p, &in) != 1) {
            LOG_JOURNAL(LOG_WARNING,
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

            rc = bpf_map_update_elem(
                bm_fd, &key, &val, BPF_ANY);

        } else {
            rc = bpf_map_update_elem(
                wl_fd, &ip, &val, BPF_ANY);
        }

        if (rc) {
            char ipbuf[INET_ADDRSTRLEN];

            fmt_ip(ip, ipbuf, sizeof(ipbuf));

            LOG_JOURNAL(LOG_WARNING,
                "whitelist: %s:%d: update failed for %s%s: %s",
                WHITELIST_CONF,
                lineno,
                ipbuf,
                is_prefix ? "/24" : "",
                strerror(errno));

            errors++;
            continue;
        }

        added++;
    }

    fclose(f);

    close(wl_fd);
    close(bm_fd);

    LOG_JOURNAL(LOG_INFO,
        "whitelist: reload from %s: %d added, %d error(s)",
        WHITELIST_CONF, added, errors);

    return errors ? -1 : 0;
}

/* ------------------------------------------------------------
 * Reload configuration and whitelist
 * ------------------------------------------------------------ */

static void reload_config(void)
{
    __u32 wake = 0;
    __u32 mode = GUARD_MODE_ENFORCE;

    if (read_config(&wake, &mode) == 0) {
        LOG_JOURNAL(LOG_INFO,
            "config: wake=%u mode=%s",
            wake,
            mode == GUARD_MODE_MONITOR ?
                "monitor" : "enforce");
    }

    load_whitelist_file(0);
}

/* ------------------------------------------------------------
 * Extract IPv4 source address from Ethernet frame.
 *
 * Supports up to two VLAN tags.
 * ------------------------------------------------------------ */

static int extract_src_ip(
    const __u8 *pkt,
    __u32 size,
    __u32 *out_ip)
{
    if (size < 14)
        return -1;

    __u16 etype =
        (__u16)((pkt[12] << 8) | pkt[13]);

    __u32 off = 14;

    for (int i = 0; i < 2; i++) {
        if (etype != 0x8100 &&
            etype != 0x88a8 &&
            etype != 0x9100)
            break;

        if (size < off + 4)
            return -1;

        etype =
            (__u16)((pkt[off + 2] << 8) |
                    pkt[off + 3]);

        off += 4;
    }

    if (etype != 0x0800 || size < off + 20)
        return -1;

    memcpy(out_ip, pkt + off + 12, 4);

    return 0;
}

/* ------------------------------------------------------------
 * Perf event callback
 *
 * META_MAGIC:
 *   enforce event, packet dropped
 *
 * META_MAGIC_MONITOR:
 *   monitor event, packet allowed
 *
 * Legacy events without metadata are treated as drops.
 * ------------------------------------------------------------ */

static void handle_event(
    void *ctx,
    int cpu,
    void *data,
    __u32 size)
{
    (void)ctx;
    (void)cpu;

    if (size < sizeof(struct meta_event))
        return;

    struct meta_event meta;

    memcpy(&meta, data, sizeof(meta));

    const __u8 *pkt;
    __u32 pkt_size;

    int monitor = 0;

    if (meta.magic == META_MAGIC ||
        meta.magic == META_MAGIC_MONITOR) {

        monitor = (meta.magic == META_MAGIC_MONITOR);

        pkt = (const __u8 *)data + sizeof(meta);

        pkt_size = size - (__u32)sizeof(meta);

    } else {
        /*
         * Legacy event without metadata.
         * Preserve original drop handling.
         */
        meta.ifindex = 0;

        pkt = (const __u8 *)data;

        pkt_size = size;
    }

    const char *action =
        monitor ? "monitor" : "drop";

    char ifname[IF_NAMESIZE] = "?";

    if (meta.ifindex > 0) {
        if (if_indextoname(meta.ifindex, ifname) == NULL)
            snprintf(ifname, sizeof(ifname),
                     "if%u", meta.ifindex);
    }

    if (pkt_size >= 14) {
        __u32 src_ip = 0;

        char ipbuf[INET_ADDRSTRLEN] = "<?>";

        if (extract_src_ip(pkt, pkt_size, &src_ip) == 0) {
            fmt_ip(src_ip, ipbuf, sizeof(ipbuf));

            __u64 count = bump_source_count(src_ip);

            LOG_JOURNAL(
                monitor ? LOG_NOTICE : LOG_WARNING,
                "%s iface=%s src_ip=%s source_total=%llu caplen=%u",
                action,
                ifname,
                ipbuf,
                (unsigned long long)count,
                pkt_size
            );

        } else {
            LOG_JOURNAL(
                monitor ? LOG_NOTICE : LOG_WARNING,
                "%s iface=%s (unparsed) caplen=%u",
                action,
                ifname,
                pkt_size
            );
        }

    } else if (pkt_size > 0) {

        LOG_JOURNAL(
            monitor ? LOG_NOTICE : LOG_WARNING,
            "%s iface=%s (short frame) caplen=%u",
            action,
            ifname,
            pkt_size
        );

    } else {

        LOG_JOURNAL(
            monitor ? LOG_NOTICE : LOG_WARNING,
            "%s iface=%s (zero-length frame)",
            action,
            ifname
        );
    }

#ifdef HAVE_PCAP
    /*
     * PCAP records dropped packets only.
     * Monitor events are allowed packets.
     */
    if (!monitor && g_pcap) {
        if (pcap_writer_write(
                g_pcap,
                pkt,
                pkt_size,
                pkt_size) == 0) {
            g_pcap_written++;
        }
    }
#endif
}

/* ------------------------------------------------------------
 * Perf buffer lost callback
 * ------------------------------------------------------------ */

static void handle_lost(
    void *ctx,
    int cpu,
    __u64 cnt)
{
    (void)ctx;

    LOG_JOURNAL(LOG_WARNING,
        "perf buffer lost %llu event(s) on cpu %d",
        (unsigned long long)cnt, cpu);
}

/* ------------------------------------------------------------
 * PID file
 * ------------------------------------------------------------ */

static int write_pid_file(void)
{
    char tmp[64];

    snprintf(tmp, sizeof(tmp), "%s.XXXXXX", PID_FILE);

    int fd = mkstemp(tmp);

    if (fd < 0) {
        LOG_JOURNAL(LOG_ERR,
            "pid: cannot create temp file for %s: %s",
            PID_FILE, strerror(errno));

        return -1;
    }

    char buf[32];

    int n = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());

    if (write(fd, buf, n) != n) {
        LOG_JOURNAL(LOG_ERR,
            "pid: short write to %s: %s",
            PID_FILE, strerror(errno));

        close(fd);
        unlink(tmp);

        return -1;
    }

    close(fd);

    if (rename(tmp, PID_FILE) != 0) {
        LOG_JOURNAL(LOG_ERR,
            "pid: rename %s -> %s: %s",
            tmp, PID_FILE, strerror(errno));

        unlink(tmp);

        return -1;
    }

    return 0;
}

static void remove_pid_file(void)
{
    if (unlink(PID_FILE) != 0 && errno != ENOENT) {
        LOG_JOURNAL(LOG_WARNING,
            "pid: cannot remove %s: %s",
            PID_FILE, strerror(errno));
    }
}

/* ------------------------------------------------------------
 * Usage
 * ------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [-d] [-h] [-p pcap_path]\n"
        "\n"
        "  -d           daemonize (background, detach from tty)\n"
        "  -p <path>    write dropped packets to a pcap file\n"
#ifdef HAVE_PCAP
        "               (enabled in this build)\n"
#else
        "               (NOT available: built without libpcap)\n"
#endif
        "  -h, --help   show this help\n",
        prog);
}

/* ------------------------------------------------------------
 * PCAP cleanup
 * ------------------------------------------------------------ */

static void cleanup_pcap(void)
{
#ifdef HAVE_PCAP
    if (g_pcap) {
        pcap_writer_close(g_pcap);
        g_pcap = NULL;
    }
#endif
}

/* ------------------------------------------------------------
 * Main
 * ------------------------------------------------------------ */

int main(int argc, char **argv)
{
    struct perf_buffer *pb = NULL;

    int events_fd;

    int c;

    int daemonize = 0;

    const char *pcap_path = NULL;

    while ((c = getopt(argc, argv, "dhp:")) != -1) {
        switch (c) {
        case 'd':
            daemonize = 1;
            break;

        case 'p':
            pcap_path = optarg;
            break;

        case 'h':
            usage(argv[0]);
            return 0;

        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* --------------------------------------------------------
     * Daemonization
     * -------------------------------------------------------- */

    if (daemonize) {
        pid_t pid = fork();

        if (pid < 0) {
            perror("fork");
            return 1;
        }

        if (pid > 0)
            _exit(0);

        if (setsid() < 0) {
            LOG_JOURNAL(LOG_ERR,
                "daemonize: setsid: %s",
                strerror(errno));

            return 1;
        }

        umask(0);

        if (chdir("/") != 0) {
            LOG_JOURNAL(LOG_WARNING,
                "daemonize: chdir(/): %s",
                strerror(errno));
        }

        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

#ifndef HAVE_SD_JOURNAL
    openlog("mtcp-guardd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
#endif

    LOG_JOURNAL(LOG_INFO,
        "mtcp-guardd starting (pid=%d, daemonized=%d)",
        (int)getpid(), daemonize);

    if (write_pid_file() != 0) {
        LOG_JOURNAL(LOG_WARNING,
            "continuing without pid file; 'remove' may not find the pid");
    }

    /* --------------------------------------------------------
     * Signal handlers
     * -------------------------------------------------------- */

    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = handle_sighup;

    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGHUP, &sa, NULL) != 0) {
        LOG_JOURNAL(LOG_ERR,
            "sigaction(SIGHUP): %s",
            strerror(errno));

        remove_pid_file();

        return 1;
    }

    sa.sa_handler = handle_stop;

    if (sigaction(SIGTERM, &sa, NULL) != 0 ||
        sigaction(SIGINT, &sa, NULL) != 0) {

        LOG_JOURNAL(LOG_ERR,
            "sigaction(SIGTERM/SIGINT): %s",
            strerror(errno));

        remove_pid_file();

        return 1;
    }

    /* --------------------------------------------------------
     * Optional PCAP
     * -------------------------------------------------------- */

    if (pcap_path) {
#ifdef HAVE_PCAP
        g_pcap = pcap_writer_open(pcap_path, MAX_CAPTURE);

        if (!g_pcap) {
            LOG_JOURNAL(LOG_ERR,
                "pcap: cannot open %s",
                pcap_path);

            remove_pid_file();

            return 1;
        }

        LOG_JOURNAL(LOG_INFO,
            "pcap: writing drops to %s",
            pcap_path);

#else
        LOG_JOURNAL(LOG_ERR,
            "-p given but this build has no libpcap support");

        remove_pid_file();

        return 1;
#endif
    }

    /* --------------------------------------------------------
     * Open pinned perf event map
     * -------------------------------------------------------- */

    events_fd = bpf_obj_get(EVENTS_PIN);

    if (events_fd < 0) {
        LOG_JOURNAL(LOG_ERR,
            "events: cannot open %s: %s\n"
            "  hint: is the guard loaded and pinned? check:\n"
            "    sudo bpftool prog show\n"
            "    sudo ls -la /sys/fs/bpf/",
            EVENTS_PIN, strerror(errno));

        cleanup_pcap();

        remove_pid_file();

        return 1;
    }

    /* --------------------------------------------------------
     * Create perf buffer.
     *
     * libbpf < 0.6:
     *   perf_buffer__new(fd, page_cnt, opts)
     *
     * libbpf 0.6 .. 0.8:
     *   perf_buffer__new(fd, opts)
     *
     * libbpf >= 1.0:
     *   perf_buffer__new(fd, page_cnt, sample_cb,
     *                    lost_cb, ctx, opts)
     * -------------------------------------------------------- */

#if LIBBPF_MAJOR_VERSION >= 1

    pb = perf_buffer__new(
        events_fd,
        PERF_BUFFER_PAGES_PER_CPU,
        handle_event,
        handle_lost,
        NULL,
        NULL
    );

#elif LIBBPF_MAJOR_VERSION == 0 && LIBBPF_MINOR_VERSION >= 6

    struct perf_buffer_opts pb_opts = {
        .sample_cb = handle_event,
        .lost_cb   = handle_lost,
        .ctx       = NULL,
        .page_cnt  = PERF_BUFFER_PAGES_PER_CPU,
    };

    pb = perf_buffer__new(events_fd, &pb_opts);

#else

    struct perf_buffer_opts pb_opts = {
        .sample_cb = handle_event,
        .lost_cb   = handle_lost,
        .ctx       = NULL,
    };

    pb = perf_buffer__new(
        events_fd,
        PERF_BUFFER_PAGES_PER_CPU,
        &pb_opts
    );

#endif

    if (!pb) {
        LOG_JOURNAL(LOG_ERR,
            "perf_buffer: cannot create buffer: %s",
            strerror(errno));

        close(events_fd);

        cleanup_pcap();

        remove_pid_file();

        return 1;
    }

    /* --------------------------------------------------------
     * Initial configuration and whitelist load
     * -------------------------------------------------------- */

    reload_config();

    LOG_JOURNAL(LOG_INFO,
        "mtcp-guardd ready");

    /* --------------------------------------------------------
     * Main event loop
     * -------------------------------------------------------- */

    while (!g_stop) {
        int err = perf_buffer__poll(pb, 1000);

        if (err < 0 && err != -EINTR) {
            LOG_JOURNAL(LOG_WARNING,
                "perf_buffer_poll: %s",
                strerror(-err));
        }

        if (g_reload) {
            g_reload = 0;

            LOG_JOURNAL(LOG_INFO,
                "received SIGHUP, reloading");

            reload_config();
        }
    }

    /* --------------------------------------------------------
     * Shutdown
     * -------------------------------------------------------- */

#ifdef HAVE_PCAP

    LOG_JOURNAL(LOG_INFO,
        "mtcp-guardd shutting down (pcap_written=%llu)",
        g_pcap_written);

#else

    LOG_JOURNAL(LOG_INFO,
        "mtcp-guardd shutting down");

#endif

    perf_buffer__free(pb);

    close(events_fd);

    cleanup_pcap();

    remove_pid_file();

#ifndef HAVE_SD_JOURNAL
    closelog();
#endif

    return 0;
}
