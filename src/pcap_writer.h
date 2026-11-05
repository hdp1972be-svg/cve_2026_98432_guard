#ifndef PCAP_WRITER_H
#define PCAP_WRITER_H

#include <stddef.h>
#include <stdint.h>

/* Opaque handle. */
typedef struct pcap_writer pcap_writer_t;

/* Open a pcap file for writing. Returns NULL on error. */
pcap_writer_t *pcap_writer_open(const char *path, int snaplen);

/* Write one packet. Returns 0 on success, -1 on error. */
int pcap_writer_write(pcap_writer_t *w,
                      const void *pkt, uint32_t caplen, uint32_t wirelen);

/* Close and free. Safe to call with NULL. */
void pcap_writer_close(pcap_writer_t *w);

#endif
