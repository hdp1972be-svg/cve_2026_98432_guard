/*
 * mtcp-guard-ctl — configuration utility for cve_2026_98432 XDP guard.
 *
 * Subcommands:
 *   whitelist add <ip>            add exact IP to whitelist
 *   whitelist add <ip>/24         add /24 prefix to whitelist
 *   whitelist remove <ip>         remove exact IP
 *   whitelist remove <ip>/24      remove /24 prefix
 *   whitelist list                list whitelist entries
 *   whitelist load <file>         bulk-load whitelist
 *   whitelist save <file>         save whitelist
 *
 *   wake on|off                   set wake bypass (config key 0)
 *
 *   mode monitor                  set monitor mode (config key 1)
 *   mode enforce                  set enforce mode (config key 1)
 *   mode show                     display current mode
 *
 *   stats                         aggregated per-CPU statistics
 *   drop-ips                      per-source matching packet counts
 *
 * Configuration map:
 *   key 0 = wake: 0 off, 1 on
 *   key 1 = mode: 0 enforce, 1 monitor
 *
 * Statistics map:
 *   key 0 = enforced drops
 *   key 1 = malformed IPv4 passed
 *   key 2 = wake bypasses
 *   key 3 = monitor detections
 *
 * All maps accessed through pinned paths under /sys/fs/bpf/.
 */

#define _GNU_SOURCE

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <linux/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>

#ifndef BPF_NOEXIST
#define BPF_NOEXIST 1
#endif

#ifndef BPF_EXIST
#define BPF_EXIST 2
#endif

#define WHITELIST_PIN    "/sys/fs/bpf/cve_2026_98432_whitelist"
#define WHITELIST_BM_PIN "/sys/fs/bpf/cve_2026_98432_whitelist_bm"
#define DROP_IPS_PIN     "/sys/fs/bpf/cve_2026_98432_drop_ips"
#define CONFIG_PIN       "/sys/fs/bpf/cve_2026_98432_config"
#define STATS_PIN        "/sys/fs/bpf/cve_2026_98432_stats"

/* Configuration keys. Must match the BPF program. */

#define CONFIG_KEY_WAKE 0
#define CONFIG_KEY_MODE 1

#define MODE_ENFORCE 0
#define MODE_MONITOR 1

/* Statistics keys. Must match cve_2026_98432_guard.c. */

#define STAT_TCP_IP_OPTIONS_DROP    0
#define STAT_MALFORMED_IPV4_PASS    1
#define STAT_TCP_IP_OPTIONS_WAKE    2
#define STAT_TCP_IP_OPTIONS_MONITOR 3

#define STATS_KEYS 4

/*
 * Mirror of prefix24() in cve_2026_98432_guard.c.
 *
 * ip->saddr is the raw packet bytes viewed as __u32.
 * No byte swap is needed.
 */

static inline __u32 prefix24(__u32 ip)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ip & 0x00ffffffU;
#else
    return ip & 0xffffff00U;
#endif
}

/* ---- map helpers ---- */

static int map_fd(const char *path)
{
    int fd = bpf_obj_get(path);

    if (fd < 0) {
        fprintf(stderr,
                "cannot open map %s: %s\n",
                path,
                strerror(errno));

        if (errno == ENOENT) {
            fprintf(stderr,
                "  hint: is the guard loaded and pinned? check:\n"
                "    sudo bpftool prog show\n"
                "    sudo ls -la /sys/fs/bpf/\n");
        }
    }

    return fd;
}

/*
 * Read one u32 configuration entry.
 */

static int config_get(__u32 key, __u32 *value)
{
    int fd = map_fd(CONFIG_PIN);

    if (fd < 0)
        return -1;

    int err = bpf_map_lookup_elem(fd, &key, value);

    if (err) {
        fprintf(stderr,
                "read config key %u: %s\n",
                key,
                strerror(errno));
    }

    close(fd);
    return err;
}

/*
 * Update one u32 configuration entry.
 *
 * This function deliberately updates only the supplied key.
 * Wake and mode are independent.
 */

static int config_set(__u32 key, __u32 value)
{
    int fd = map_fd(CONFIG_PIN);

    if (fd < 0)
        return -1;

    int err = bpf_map_update_elem(
        fd,
        &key,
        &value,
        BPF_ANY
    );

    if (err) {
        fprintf(stderr,
                "update config key %u: %s\n",
                key,
                strerror(errno));
    }

    close(fd);
    return err;
}

/* ---- IP helpers ---- */

static void print_ip(__u32 ip)
{
    struct in_addr in;
    char buf[INET_ADDRSTRLEN];

    in.s_addr = ip;

    if (inet_ntop(AF_INET, &in, buf, sizeof(buf)))
        fputs(buf, stdout);
    else
        fputs("<?>", stdout);
}

/*
 * Parse "a.b.c.d" or "a.b.c.d/24" into (ip, is_prefix).
 *
 * Returns 0 on success, -1 on error.
 * Modifies str in place.
 */

static int parse_ip_arg(
    char *str,
    __u32 *out_ip,
    int *out_is_prefix
)
{
    int is_prefix = 0;

    char *slash = strchr(str, '/');

    if (slash) {
        *slash = '\0';

        if (strcmp(slash + 1, "24") != 0) {
            fprintf(stderr,
                    "only /24 is supported, got /%s\n",
                    slash + 1);
            return -1;
        }

        is_prefix = 1;
    }

    struct in_addr in;

    if (inet_pton(AF_INET, str, &in) != 1) {
        fprintf(stderr, "invalid IP: %s\n", str);
        return -1;
    }

    memcpy(out_ip, &in.s_addr, sizeof(*out_ip));

    *out_is_prefix = is_prefix;

    return 0;
}

/* ---- whitelist operations ---- */

static int whitelist_insert(
    __u32 ip,
    int is_prefix,
    int quiet
)
{
    int err;

    if (is_prefix) {
        __u32 key = prefix24(ip);
        __u8 val = 1;

        int fd = map_fd(WHITELIST_BM_PIN);

        if (fd < 0)
            return -1;

        err = bpf_map_update_elem(
            fd,
            &key,
            &val,
            BPF_ANY
        );

        close(fd);

        if (err) {
            fprintf(stderr,
                    "update whitelist_bm: %s\n",
                    strerror(errno));
            return -1;
        }

        if (!quiet) {
            print_ip(ip);
            printf("/24 added (prefix)\n");
        }

    } else {
        __u8 val = 1;

        int fd = map_fd(WHITELIST_PIN);

        if (fd < 0)
            return -1;

        err = bpf_map_update_elem(
            fd,
            &ip,
            &val,
            BPF_ANY
        );

        close(fd);

        if (err) {
            fprintf(stderr,
                    "update whitelist: %s\n",
                    strerror(errno));
            return -1;
        }

        if (!quiet) {
            print_ip(ip);
            printf(" added (exact)\n");
        }
    }

    return 0;
}

static int whitelist_remove(
    __u32 ip,
    int is_prefix,
    int quiet
)
{
    int err;
    int fd;

    if (is_prefix) {
        __u32 key = prefix24(ip);

        fd = map_fd(WHITELIST_BM_PIN);

        if (fd < 0)
            return -1;

        err = bpf_map_delete_elem(fd, &key);

        close(fd);

    } else {
        fd = map_fd(WHITELIST_PIN);

        if (fd < 0)
            return -1;

        err = bpf_map_delete_elem(fd, &ip);

        close(fd);
    }

    if (err) {
        if (!quiet)
            fprintf(stderr,
                    "delete failed: %s\n",
                    strerror(errno));

        return -1;
    }

    if (!quiet) {
        print_ip(ip);
        printf("%s removed\n", is_prefix ? "/24" : "");
    }

    return 0;
}

/* ---- whitelist subcommands ---- */

static int cmd_whitelist_add(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr,
                "Usage: mtcp-guard-ctl whitelist add <ip>[/24]\n");
        return 1;
    }

    __u32 ip;
    int is_prefix;

    if (parse_ip_arg(argv[0], &ip, &is_prefix) != 0)
        return 1;

    return whitelist_insert(ip, is_prefix, 0) == 0 ? 0 : 1;
}

static int cmd_whitelist_remove(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr,
                "Usage: mtcp-guard-ctl whitelist remove <ip>[/24]\n");
        return 1;
    }

    __u32 ip;
    int is_prefix;

    if (parse_ip_arg(argv[0], &ip, &is_prefix) != 0)
        return 1;

    return whitelist_remove(ip, is_prefix, 0) == 0 ? 0 : 1;
}

static int cmd_whitelist_list(void)
{
    int fd;
    __u32 next_key;

    fd = map_fd(WHITELIST_PIN);

    if (fd < 0)
        return 1;

    printf("--- whitelist (exact IPs) ---\n");

    /*
     * NULL retrieves the first key, including key 0.
     */

    while (bpf_map_get_next_key(fd, NULL, &next_key) == 0) {
        __u8 val;

        if (bpf_map_lookup_elem(fd, &next_key, &val) == 0 && val) {
            print_ip(next_key);
            putchar('\n');
        }

        __u32 current_key = next_key;

        while (bpf_map_get_next_key(
                   fd,
                   &current_key,
                   &next_key
               ) == 0) {

            if (bpf_map_lookup_elem(
                    fd,
                    &next_key,
                    &val
                ) == 0 && val) {
                print_ip(next_key);
                putchar('\n');
            }

            current_key = next_key;
        }

        break;
    }

    close(fd);

    fd = map_fd(WHITELIST_BM_PIN);

    if (fd < 0)
        return 1;

    printf("--- whitelist (/24 prefixes) ---\n");

    __u32 current_key;

    if (bpf_map_get_next_key(fd, NULL, &next_key) == 0) {
        for (;;) {
            __u8 val;

            if (bpf_map_lookup_elem(
                    fd,
                    &next_key,
                    &val
                ) == 0 && val) {
                print_ip(next_key);
                printf("/24\n");
            }

            current_key = next_key;

            if (bpf_map_get_next_key(
                    fd,
                    &current_key,
                    &next_key
                ) != 0)
                break;
        }
    }

    close(fd);

    return 0;
}

static int cmd_whitelist_load(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr,
                "Usage: mtcp-guard-ctl whitelist load <file>\n");
        return 1;
    }

    FILE *f = fopen(argv[0], "r");

    if (!f) {
        fprintf(stderr,
                "cannot open %s: %s\n",
                argv[0],
                strerror(errno));
        return 1;
    }

    char line[256];

    int lineno = 0;
    int errors = 0;
    int added = 0;

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

        __u32 ip;
        int is_prefix;

        if (parse_ip_arg(p, &ip, &is_prefix) != 0) {
            fprintf(stderr,
                    "%s:%d: skipped\n",
                    argv[0],
                    lineno);
            errors++;
            continue;
        }

        if (whitelist_insert(ip, is_prefix, 1) != 0) {
            errors++;
            continue;
        }

        added++;
    }

    fclose(f);

    printf("whitelist loaded from %s (%d added, %d error(s))\n",
           argv[0],
           added,
           errors);

    return errors ? 1 : 0;
}

static int cmd_whitelist_save(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr,
                "Usage: mtcp-guard-ctl whitelist save <file>\n");
        return 1;
    }

    FILE *f = fopen(argv[0], "w");

    if (!f) {
        fprintf(stderr,
                "cannot open %s for writing: %s\n",
                argv[0],
                strerror(errno));
        return 1;
    }

    fprintf(f, "# cve_2026_98432_guard whitelist\n");
    fprintf(f, "# Format: IP or IP/24 per line\n");

    int fd = map_fd(WHITELIST_PIN);

    if (fd < 0) {
        fclose(f);
        return 1;
    }

    __u32 next_key;

    if (bpf_map_get_next_key(fd, NULL, &next_key) == 0) {
        for (;;) {
            __u8 val;

            if (bpf_map_lookup_elem(
                    fd,
                    &next_key,
                    &val
                ) == 0 && val) {
                struct in_addr in;
                char buf[INET_ADDRSTRLEN];

                in.s_addr = next_key;

                if (inet_ntop(AF_INET, &in, buf, sizeof(buf)))
                    fprintf(f, "%s\n", buf);
            }

            __u32 current_key = next_key;

            if (bpf_map_get_next_key(
                    fd,
                    &current_key,
                    &next_key
                ) != 0)
                break;
        }
    }

    close(fd);

    fd = map_fd(WHITELIST_BM_PIN);

    if (fd < 0) {
        fclose(f);
        return 1;
    }

    if (bpf_map_get_next_key(fd, NULL, &next_key) == 0) {
        for (;;) {
            __u8 val;

            if (bpf_map_lookup_elem(
                    fd,
                    &next_key,
                    &val
                ) == 0 && val) {
                struct in_addr in;
                char buf[INET_ADDRSTRLEN];

                in.s_addr = next_key;

                if (inet_ntop(AF_INET, &in, buf, sizeof(buf)))
                    fprintf(f, "%s/24\n", buf);
            }

            __u32 current_key = next_key;

            if (bpf_map_get_next_key(
                    fd,
                    &current_key,
                    &next_key
                ) != 0)
                break;
        }
    }

    close(fd);

    if (fclose(f) != 0) {
        fprintf(stderr,
                "write error for %s: %s\n",
                argv[0],
                strerror(errno));
        return 1;
    }

    printf("whitelist saved to %s\n", argv[0]);

    return 0;
}

/* ---- wake ---- */

/*
 * Wake remains config key 0.
 *
 * It does not modify monitor/enforce mode.
 */

static int cmd_wake(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr,
                "Usage: mtcp-guard-ctl wake on|off\n");
        return 1;
    }

    int want;

    if (strcmp(argv[0], "on") == 0)
        want = 1;
    else if (strcmp(argv[0], "off") == 0)
        want = 0;
    else {
        fprintf(stderr,
                "Usage: mtcp-guard-ctl wake on|off\n");
        return 1;
    }

    if (config_set(CONFIG_KEY_WAKE, (__u32)want) != 0)
        return 1;

    printf("wake %s\n", want ? "on" : "off");

    return 0;
}

/* ---- monitor / enforce mode ---- */

/*
 * Mode operates exclusively on config key 1.
 *
 * monitor = 1
 * enforce = 0
 */

static int cmd_mode(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr,
                "Usage: mtcp-guard-ctl mode monitor|enforce|show\n");
        return 1;
    }

    const char *arg = argv[0];

    if (strcmp(arg, "show") == 0) {
        __u32 mode;

        if (config_get(CONFIG_KEY_MODE, &mode) != 0)
            return 1;

        if (mode == MODE_MONITOR) {
            printf("mode monitor\n");
        } else if (mode == MODE_ENFORCE) {
            printf("mode enforce\n");
        } else {
            /*
             * The BPF program treats unknown values as enforce.
             */
            printf("mode enforce (stored value %u; effective default)\n",
                   mode);
        }

        return 0;
    }

    __u32 mode;

    if (strcmp(arg, "monitor") == 0) {
        mode = MODE_MONITOR;
    } else if (strcmp(arg, "enforce") == 0) {
        mode = MODE_ENFORCE;
    } else {
        fprintf(stderr,
                "Usage: mtcp-guard-ctl mode monitor|enforce|show\n");
        return 1;
    }

    if (config_set(CONFIG_KEY_MODE, mode) != 0)
        return 1;

    printf("mode %s\n",
           mode == MODE_MONITOR ? "monitor" : "enforce");

    return 0;
}

/* ---- statistics ---- */

static int cmd_stats(void)
{
    int fd = map_fd(STATS_PIN);

    if (fd < 0)
        return 1;

    int nr_cpus = libbpf_num_possible_cpus();

    if (nr_cpus <= 0) {
        fprintf(stderr,
                "libbpf_num_possible_cpus failed: %s\n",
                strerror(errno));
        close(fd);
        return 1;
    }

    __u64 *vals = calloc(
        (size_t)nr_cpus,
        sizeof(*vals)
    );

    if (!vals) {
        fprintf(stderr, "calloc failed\n");
        close(fd);
        return 1;
    }

    printf("--- XDP statistics (aggregated across %d CPUs) ---\n",
           nr_cpus);

    for (__u32 key = 0; key < STATS_KEYS; key++) {
        memset(
            vals,
            0,
            (size_t)nr_cpus * sizeof(*vals)
        );

        if (bpf_map_lookup_elem(fd, &key, vals) != 0) {
            fprintf(stderr,
                    "lookup key %u: %s\n",
                    key,
                    strerror(errno));
            continue;
        }

        __u64 total = 0;

        for (int i = 0; i < nr_cpus; i++)
            total += vals[i];

        const char *name;

        switch (key) {
        case STAT_TCP_IP_OPTIONS_DROP:
            name = "TCP/IP-options enforced drops";
            break;

        case STAT_MALFORMED_IPV4_PASS:
            name = "Malformed IPv4 passed";
            break;

        case STAT_TCP_IP_OPTIONS_WAKE:
            name = "Wake-mode bypasses";
            break;

        case STAT_TCP_IP_OPTIONS_MONITOR:
            name = "TCP/IP-options monitor detections";
            break;

        default:
            name = "?";
            break;
        }

        printf("  key %u (%s): %llu\n",
               key,
               name,
               (unsigned long long)total);

        for (int i = 0; i < nr_cpus; i++) {
            if (vals[i]) {
                printf("    cpu %d: %llu\n",
                       i,
                       (unsigned long long)vals[i]);
            }
        }
    }

    free(vals);
    close(fd);

    return 0;
}

/* ---- per-source matching packet counters ---- */

static int cmd_drop_ips(void)
{
    int fd = map_fd(DROP_IPS_PIN);

    if (fd < 0)
        return 1;

    printf("--- matching-source counts (monitor + enforce) ---\n");

    __u32 next_key;

    if (bpf_map_get_next_key(fd, NULL, &next_key) == 0) {
        for (;;) {
            __u64 val;

            if (bpf_map_lookup_elem(
                    fd,
                    &next_key,
                    &val
                ) == 0) {
                print_ip(next_key);

                printf(": %llu\n",
                       (unsigned long long)val);
            }

            __u32 current_key = next_key;

            if (bpf_map_get_next_key(
                    fd,
                    &current_key,
                    &next_key
                ) != 0)
                break;
        }
    }

    close(fd);

    return 0;
}

/* ---- startup sanity check ---- */

static int check_maps_present(void)
{
    static const char *required[] = {
        WHITELIST_PIN,
        WHITELIST_BM_PIN,
        STATS_PIN,
        DROP_IPS_PIN,
        CONFIG_PIN,
    };

    int missing = 0;

    for (size_t i = 0;
         i < sizeof(required) / sizeof(required[0]);
         i++) {

        if (access(required[i], F_OK) != 0) {
            fprintf(stderr,
                    "missing required pin: %s\n",
                    required[i]);
            missing++;
        }
    }

    if (missing) {
        fprintf(stderr,
            "\nhint: pin the maps after loading the guard, e.g.:\n"
            "  sudo bpftool map show\n"
            "  sudo bpftool map pin id <ID> /sys/fs/bpf/<name>\n"
            "or use the install script.\n");

        return -1;
    }

    return 0;
}

/* ---- usage ---- */

static void usage(FILE *out, const char *prog)
{
    fprintf(out,
        "Usage: %s <command> [args]\n"
        "\n"
        "Commands:\n"
        "  whitelist add <ip>[/24]      add exact IP or /24 prefix\n"
        "  whitelist remove <ip>[/24]   remove exact IP or /24 prefix\n"
        "  whitelist list               list whitelist entries\n"
        "  whitelist load <file>        bulk load whitelist\n"
        "  whitelist save <file>        save whitelist to file\n"
        "\n"
        "  wake on|off                  set wake bypass flag\n"
        "\n"
        "  mode monitor                 detect, capture and pass\n"
        "  mode enforce                 detect, capture and drop\n"
        "  mode show                    display current mode\n"
        "\n"
        "  stats                        print aggregated statistics\n"
        "  drop-ips                     print matching-source counts\n"
        "\n"
        "  -h, --help                   show this help\n",
        prog);
}

/* ---- main ---- */

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(stderr, argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "-h") == 0 ||
        strcmp(cmd, "--help") == 0) {
        usage(stdout, argv[0]);
        return 0;
    }

    /*
     * Ensure required pinned maps exist before dispatch.
     */

    if (check_maps_present() != 0)
        return 1;

    if (strcmp(cmd, "whitelist") == 0) {
        if (argc < 3) {
            fprintf(stderr,
                    "whitelist: missing subcommand\n");
            usage(stderr, argv[0]);
            return 1;
        }

        const char *sub = argv[2];

        if (strcmp(sub, "add") == 0)
            return cmd_whitelist_add(argc - 3, argv + 3);

        if (strcmp(sub, "remove") == 0)
            return cmd_whitelist_remove(argc - 3, argv + 3);

        if (strcmp(sub, "list") == 0)
            return cmd_whitelist_list();

        if (strcmp(sub, "load") == 0)
            return cmd_whitelist_load(argc - 3, argv + 3);

        if (strcmp(sub, "save") == 0)
            return cmd_whitelist_save(argc - 3, argv + 3);

        fprintf(stderr,
                "unknown whitelist subcommand: %s\n",
                sub);

        return 1;
    }

    if (strcmp(cmd, "wake") == 0)
        return cmd_wake(argc - 2, argv + 2);

    if (strcmp(cmd, "mode") == 0)
        return cmd_mode(argc - 2, argv + 2);

    if (strcmp(cmd, "stats") == 0)
        return cmd_stats();

    if (strcmp(cmd, "drop-ips") == 0)
        return cmd_drop_ips();

    fprintf(stderr, "unknown command: %s\n", cmd);

    usage(stderr, argv[0]);

    return 1;
}
