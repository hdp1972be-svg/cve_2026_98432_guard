

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static uint16_t checksum(const void *data, size_t len)
{
    const uint8_t *p = data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += ((uint16_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }

    if (len)
        sum += (uint16_t)p[0] << 8;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return htons((uint16_t)~sum);
}

static int parse_mac(const char *s, uint8_t mac[6])
{
    unsigned int b[6];

    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &b[0], &b[1], &b[2],
               &b[3], &b[4], &b[5]) != 6)
        return -1;

    for (int i = 0; i < 6; i++) {
        if (b[i] > 255)
            return -1;
        mac[i] = (uint8_t)b[i];
    }

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 5 || argc > 6) {
        fprintf(stderr,
            "Usage: %s <interface> <destination-MAC> "
            "<source-IP> <destination-IP> [destination-port]\n",
            argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    const char *dst_mac_arg = argv[2];
    const char *src_ip_arg = argv[3];
    const char *dst_ip_arg = argv[4];
    uint16_t dst_port = argc == 6 ? (uint16_t)atoi(argv[5]) : 8080;

    unsigned int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    uint8_t dst_mac[6], src_mac[6];

    if (parse_mac(dst_mac_arg, dst_mac) < 0) {
        fprintf(stderr, "Invalid destination MAC\n");
        return 1;
    }

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket(AF_PACKET)");
        return 1;
    }

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        close(fd);
        return 1;
    }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    struct in_addr src_ip, dst_ip;
    if (inet_pton(AF_INET, src_ip_arg, &src_ip) != 1 ||
        inet_pton(AF_INET, dst_ip_arg, &dst_ip) != 1) {
        fprintf(stderr, "Invalid IPv4 address\n");
        close(fd);
        return 1;
    }

    /*
     * Ethernet: 14 bytes
     * IPv4:     24 bytes (IHL=6, Record Route + NOP)
     * TCP:      20 bytes (SYN)
     */
    uint8_t frame[14 + 24 + 20] = {0};
    uint8_t *ip  = frame + 14;
    uint8_t *tcp = ip + 24;

    /* Ethernet header */
    memcpy(frame, dst_mac, 6);
    memcpy(frame + 6, src_mac, 6);
    frame[12] = 0x08;
    frame[13] = 0x00;                 /* IPv4 */

    /* IPv4 header */
    ip[0] = 0x46;                     /* Version 4, IHL 6 */
    ip[1] = 0;
    ip[2] = 0;
    ip[3] = 44;                       /* 24-byte IP + 20-byte TCP */
    ip[4] = 0x12;
    ip[5] = 0x34;                     /* Identification */
    ip[6] = 0x40;                     /* Don't Fragment */
    ip[7] = 0;
    ip[8] = 64;                       /* TTL */
    ip[9] = IPPROTO_TCP;
    memcpy(ip + 12, &src_ip.s_addr, 4);
    memcpy(ip + 16, &dst_ip.s_addr, 4);

    /* IPv4 options: Record Route (type 7, length 3, pointer 4), NOP */
    ip[20] = 0x07;
    ip[21] = 0x03;
    ip[22] = 0x04;
    ip[23] = 0x01;

    uint16_t ip_sum = checksum(ip, 24);
    memcpy(ip + 10, &ip_sum, 2);

    /* TCP SYN header */
    uint16_t src_port = htons(49152);
    uint16_t net_dst_port = htons(dst_port);
    memcpy(tcp, &src_port, 2);
    memcpy(tcp + 2, &net_dst_port, 2);

    tcp[4] = 0x01;                    /* Sequence number */
    tcp[5] = 0x02;
    tcp[6] = 0x03;
    tcp[7] = 0x04;
    tcp[12] = 0x50;                   /* Data offset = 5 */
    tcp[13] = 0x02;                   /* SYN */
    tcp[14] = 0xfa;
    tcp[15] = 0xf0;                   /* Window */

    /* TCP pseudo-header + TCP header checksum */
    uint8_t pseudo[12 + 20] = {0};
    memcpy(pseudo, &src_ip.s_addr, 4);
    memcpy(pseudo + 4, &dst_ip.s_addr, 4);
    pseudo[9] = IPPROTO_TCP;
    pseudo[10] = 0;
    pseudo[11] = 20;
    memcpy(pseudo + 12, tcp, 20);

    uint16_t tcp_sum = checksum(pseudo, sizeof(pseudo));
    memcpy(tcp + 16, &tcp_sum, 2);

    struct sockaddr_ll addr = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex = (int)ifindex,
        .sll_halen = ETH_ALEN
    };
    memcpy(addr.sll_addr, dst_mac, 6);

    ssize_t sent = sendto(fd, frame, sizeof(frame), 0,
                          (struct sockaddr *)&addr, sizeof(addr));

    if (sent < 0) {
        perror("sendto");
        close(fd);
        return 1;
    }

    printf("Sent %zd-byte Ethernet frame via %s\n", sent, iface);
    printf("IPv4 IHL: 6 (24 bytes), protocol: TCP\n");
    printf("IPv4 option: Record Route (0x07)\n");
    printf("Destination: %s:%u\n", dst_ip_arg, dst_port);

    close(fd);
    return 0;
}
