/*
 * mtcp-guard-ctl — configuration utility for cve_2026_98432 XDP guard.
 *
 * Subcommands:
 *   whitelist add <ip>          add exact IP to whitelist hash map
 *   whitelist add <ip>/24       add /24 prefix to whitelist bitmap
 *   whitelist remove <ip>       remove exact IP from whitelist hash map
 *   whitelist list              list all whitelisted IPs
 *   whitelist load <file>       bulk-load whitelist from file (one IP or IP/24 per line)
 *   whitelist save <file>       dump current whitelist maps to file
 *   wake on                     set wake flag in config map
 *   wake off                    clear wake flag in config map
 *   stats                       print per-CPU drop stats
 *   drop-ips                    print drop-IP counts from LRU map
 *
 * All maps accessed via pinned paths under /sys/fs/bpf/.
 */

#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>

#ifndef __u32
#define __u32 uint32_t
#endif
#ifndef __u8
#define __u8  uint8_t
#endif
#ifndef __u64
#define __u64 uint64_t
#endif

#ifndef BPF_NOEXIST
#define BPF_NOEXIST 1
#endif
#ifndef BPF_EXIST
#define BPF_EXIST   2
#endif

#define WHITELIST_PIN    "/sys/fs/bpf/cve_2026_98432_whitelist"
#define WHITELIST_BM_PIN "/sys/fs/bpf/cve_2026_98432_whitelist_bm"
#define DROP_IPS_PIN     "/sys/fs/bpf/cve_2026_98432_drop_ips"
#define CONFIG_PIN       "/sys/fs/bpf/cve_2026_98432_config"
#define STATS_PIN        "/sys/fs/bpf/cve_2026_98432_stats"

static int map_fd(const char *path)
{
    int fd = bpf_obj_get(path);
    if (fd < 0)
        fprintf(stderr, "cannot open map %s: %s\n", path, strerror(errno));
    return fd;
}

static __u32 ntoh32(__u32 v)
{
    return __builtin_bswap32(v);
}

static void print_ip(__u32 ip)
{
    struct in_addr in;
    in.s_addr = ip;
    printf("%s", inet_ntoa(in));
}

static int cmd_whitelist_add(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s whitelist add <ip> [/24]\n", argv[0]);
        return 1;
    }

    char *ip_str = argv[1];
    char *slash = strchr(ip_str, '/');
    int is_bm = 0;
    __u32 ip = 0;

    if (slash) {
        *slash = '\0';
        if (strcmp(slash + 1, "24") == 0)
            is_bm = 1;
    }

    if (inet_pton(AF_INET, ip_str, &ip) != 1) {
        fprintf(stderr, "invalid IP: %s\n", ip_str);
        return 1;
    }
    ip = ntoh32(ip); /* network -> host */

    if (is_bm) {
        /* Bitmap: idx = ip >> 8, bit = 1 << ((ip >> 3) & 0x1f) */
        int fd = map_fd(WHITELIST_BM_PIN);
        if (fd < 0) return 1;
        __u32 idx = ip >> 8;
        __u32 bit = 1 << ((ip >> 3) & 0x1f);
        __u32 cur = 0;
        if (bpf_map_lookup_elem(fd, &idx, &cur) < 0) {
            cur = 0;
        }
        cur |= bit;
        if (bpf_map_update_elem(fd, &idx, &cur, BPF_EXIST) < 0 &&
            bpf_map_update_elem(fd, &idx, &cur, BPF_NOEXIST) < 0) {
            fprintf(stderr, "failed to update bitmap: %s\n", strerror(errno));
            close(fd);
            return 1;
        }
        close(fd);
        printf("whitelisted %s/24 (bitmap)\n", ip_str);
    } else {
        int fd = map_fd(WHITELIST_PIN);
        if (fd < 0) return 1;
        __u8 val = 1;
        if (bpf_map_update_elem(fd, &ip, &val, BPF_NOEXIST) < 0 &&
            bpf_map_update_elem(fd, &ip, &val, BPF_EXIST) < 0) {
            fprintf(stderr, "failed to update whitelist: %s\n", strerror(errno));
            close(fd);
            return 1;
        }
        close(fd);
        printf("whitelisted %s (hash)\n", ip_str);
    }
    return 0;
}

static int cmd_whitelist_remove(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s whitelist remove <ip>\n", argv[0]);
        return 1;
    }

    __u32 ip;
    if (inet_pton(AF_INET, argv[1], &ip) != 1) {
        fprintf(stderr, "invalid IP: %s\n", argv[1]);
        return 1;
    }
    ip = ntoh32(ip);

    int fd = map_fd(WHITELIST_PIN);
    if (fd < 0) return 1;
    if (bpf_map_delete_elem(fd, &ip) < 0)
        fprintf(stderr, "delete failed (may not exist): %s\n", strerror(errno));
    else
        printf("removed %s from whitelist\n", argv[1]);
    close(fd);
    return 0;
}

static int cmd_whitelist_list(void)
{
    int fd = map_fd(WHITELIST_PIN);
    if (fd < 0) return 1;

    printf("--- whitelist hash (exact IPs) ---\n");
    __u32 key = 0, next_key = 0;
    __u8 val;
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &val) == 0) {
            print_ip(ntoh32(next_key));
            printf("\n");
        }
        key = next_key;
    }
    close(fd);

    fd = map_fd(WHITELIST_BM_PIN);
    if (fd < 0) return 1;

    printf("--- whitelist bitmap (/24 prefixes) ---\n");
    __u32 bm_key = 0, bm_next = 0;
    __u32 bm_val;
    while (bpf_map_get_next_key(fd, &bm_key, &bm_next) == 0) {
        if (bpf_map_lookup_elem(fd, &bm_next, &bm_val) == 0) {
            if (bm_val) {
                /* Reconstruct /24 prefix from idx */
                struct in_addr in;
                __u32 prefix = ntoh32(bm_next << 8);
                in.s_addr = prefix;
                printf("%s/24 (bits=0x%08x)\n", inet_ntoa(in), bm_val);
            }
        }
        bm_key = bm_next;
    }
    close(fd);
    return 0;
}

/* ---- whitelist load / save (persistent file) ---- */

#define WHITELIST_CONF_MAX_LINE 256

static int do_whitelist_add_entry(const char *ip_str)
{
    char *slash = strchr(ip_str, '/');
    int is_bm = 0;
    __u32 ip = 0;

    if (slash) {
        *slash = '\0';
        if (strcmp(slash + 1, "24") == 0)
            is_bm = 1;
        else
            return 0; /* only /24 supported in bulk load */
    }

    if (inet_pton(AF_INET, ip_str, &ip) != 1) {
        fprintf(stderr, "invalid IP: %s\n", ip_str);
        return 1;
    }
    ip = ntoh32(ip); /* network -> host */

    if (is_bm) {
        int fd = map_fd(WHITELIST_BM_PIN);
        if (fd < 0) return 1;
        __u32 idx = ip >> 8;
        __u32 bit = 1 << ((ip >> 3) & 0x1f);
        __u32 cur = 0;
        if (bpf_map_lookup_elem(fd, &idx, &cur) < 0)
            cur = 0;
        cur |= bit;
        if (bpf_map_update_elem(fd, &idx, &cur, BPF_EXIST) < 0 &&
            bpf_map_update_elem(fd, &idx, &cur, BPF_NOEXIST) < 0) {
            fprintf(stderr, "failed to update bitmap for %s: %s\n", ip_str, strerror(errno));
            close(fd);
            return 1;
        }
        close(fd);
        printf("whitelisted %s/24 (bitmap)\n", ip_str);
    } else {
        int fd = map_fd(WHITELIST_PIN);
        if (fd < 0) return 1;
        __u8 val = 1;
        if (bpf_map_update_elem(fd, &ip, &val, BPF_NOEXIST) < 0 &&
            bpf_map_update_elem(fd, &ip, &val, BPF_EXIST) < 0) {
            fprintf(stderr, "failed to update whitelist for %s: %s\n", ip_str, strerror(errno));
            close(fd);
            return 1;
        }
        close(fd);
        printf("whitelisted %s (hash)\n", ip_str);
    }
    return 0;
}

static int cmd_whitelist_load(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s whitelist load <file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "r");
    if (!f) {
        fprintf(stderr, "cannot open %s: %s\n", argv[1], strerror(errno));
        return 1;
    }

    char line[WHITELIST_CONF_MAX_LINE];
    int lineno = 0;
    int errors = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        /* Strip trailing newline/CR */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        /* Skip blank lines and comments */
        if (len == 0 || line[0] == '#')
            continue;

        /* Trim leading whitespace */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#')
            continue;

        if (do_whitelist_add_entry(p) != 0)
            errors++;
    }

    fclose(f);

    if (errors > 0)
        fprintf(stderr, "whitelist load completed with %d error(s)\n", errors);

    printf("whitelist loaded from %s\n", argv[1]);
    return errors ? 1 : 0;
}

static int cmd_whitelist_save(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s whitelist save <file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "w");
    if (!f) {
        fprintf(stderr, "cannot open %s for writing: %s\n", argv[1], strerror(errno));
        return 1;
    }

    fprintf(f, "# cve_2026_98432_guard whitelist\n");
    fprintf(f, "# One entry per line: IP or IP/24\n");
    fprintf(f, "# Lines starting with # are comments\n");

    /* Save exact-match hash entries */
    int fd = map_fd(WHITELIST_PIN);
    if (fd >= 0) {
        __u32 key = 0, next_key = 0;
        __u8 val;
        while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(fd, &next_key, &val) == 0 && val) {
                char ip[INET_ADDRSTRLEN];
                struct in_addr in;
                in.s_addr = ntoh32(next_key);
                inet_ntop(AF_INET, &in, ip, sizeof(ip));
                fprintf(f, "%s\n", ip);
            }
            key = next_key;
        }
        close(fd);
    }

    /* Save bitmap (/24 prefix) entries */
    fd = map_fd(WHITELIST_BM_PIN);
    if (fd >= 0) {
        __u32 bm_key = 0, bm_next = 0;
        __u32 bm_val;
        while (bpf_map_get_next_key(fd, &bm_key, &bm_next) == 0) {
            if (bpf_map_lookup_elem(fd, &bm_next, &bm_val) == 0 && bm_val) {
                struct in_addr in;
                __u32 prefix = ntoh32(bm_next << 8);
                in.s_addr = prefix;
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &in, ip, sizeof(ip));
                fprintf(f, "%s/24\n", ip);
            }
            bm_key = bm_next;
        }
        close(fd);
    }

    fclose(f);
    printf("whitelist saved to %s\n", argv[1]);
    return 0;
}

static int cmd_wake(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s wake on|off\n", argv[0]);
        return 1;
    }

    int fd = map_fd(CONFIG_PIN);
    if (fd < 0) return 1;

    __u32 key = 0;
    __u32 val = (strcmp(argv[1], "on") == 0) ? 1 : 0;
    if (strcmp(argv[1], "on") != 0 && strcmp(argv[1], "off") != 0) {
        fprintf(stderr, "Usage: %s wake on|off\n", argv[0]);
        close(fd);
        return 1;
    }

    if (bpf_map_update_elem(fd, &key, &val, BPF_EXIST) < 0 &&
        bpf_map_update_elem(fd, &key, &val, BPF_NOEXIST) < 0) {
        fprintf(stderr, "failed to update config: %s\n", strerror(errno));
        close(fd);
        return 1;
    }
    printf("wake %s\n", argv[1]);
    close(fd);
    return 0;
}

static int cmd_stats(void)
{
    int fd = map_fd(STATS_PIN);
    if (fd < 0) return 1;

    /* Per-CPU array: dump all CPUs for keys 0 and 1 */
    printf("--- XDP statistics (per-CPU) ---\n");
    for (int cpu = 0; cpu < 1024; cpu++) {
        char path[256];
        snprintf(path, sizeof(path), "/sys/fs/bpf/cve_2026_98432_stats_cpu_%d", cpu);
        /* Per-CPU maps are read via bpftool or sysfs; here we use libbpf
           with CPU-specific fd. Fallback: just show aggregate via bpf_map_lookup_elem
           on key 0 and key 1 (returns current CPU value). */
        break;
    }
    /* Simple read (current CPU only) */
    __u32 key;
    __u64 val;
    for (key = 0; key < 2; key++) {
        if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
            const char *name = (key == 0) ? "TCP/IP-options drops" : "Malformed IPv4 pass";
            printf("  key %u (%s): %llu\n", key, name, (unsigned long long)val);
        }
    }
    close(fd);
    return 0;
}

static int cmd_drop_ips(void)
{
    int fd = map_fd(DROP_IPS_PIN);
    if (fd < 0) return 1;

    printf("--- drop-IP counts ---\n");
    __u32 key = 0, next_key = 0;
    __u64 val;
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &val) == 0) {
            print_ip(ntoh32(next_key));
            printf(": %llu\n", (unsigned long long)val);
        }
        key = next_key;
    }
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <command> [args]\n"
            "Commands:\n"
            "  whitelist add <ip> [/24]\n"
            "  whitelist remove <ip>\n"
            "  whitelist list\n"
            "  whitelist load <file>\n"
            "  whitelist save <file>\n"
            "  wake on|off\n"
            "  stats\n"
            "  drop-ips\n",
            argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "whitelist") == 0) {
        if (argc < 3) { fprintf(stderr, "missing subcommand\n"); return 1; }
        if (strcmp(argv[2], "add") == 0)     return cmd_whitelist_add(argc - 2, argv + 2);
        if (strcmp(argv[2], "remove") == 0)  return cmd_whitelist_remove(argc - 2, argv + 2);
        if (strcmp(argv[2], "list") == 0)    return cmd_whitelist_list();
        if (strcmp(argv[2], "load") == 0)    return cmd_whitelist_load(argc - 2, argv + 2);
        if (strcmp(argv[2], "save") == 0)    return cmd_whitelist_save(argc - 2, argv + 2);
        fprintf(stderr, "unknown whitelist subcommand: %s\n", argv[2]);
        return 1;
    }

    if (strcmp(cmd, "wake") == 0)     return cmd_wake(argc - 1, argv + 1);
    if (strcmp(cmd, "stats") == 0)    return cmd_stats();
    if (strcmp(cmd, "drop-ips") == 0) return cmd_drop_ips();

    fprintf(stderr, "unknown command: %s\n", cmd);
    return 1;
}
