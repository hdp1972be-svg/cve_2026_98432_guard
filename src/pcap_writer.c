/*
 * pcap_writer — minimal wrapper around libpcap's dumper.
 *
 * Purpose: the daemon needs to write raw dropped packets to a pcap
 * file without including <pcap/pcap.h> directly. libpcap's headers
 * conflict with <linux/bpf.h> (both define struct bpf_insn), so the
 * pcap API lives in this translation unit and the daemon talks to it
 * through pcap_writer.h.
 *
 * Every pcap_writer_write() call is followed by pcap_dump_flush(),
 * so the file is readable by tcpdump while the daemon is running.
 * Without the flush, libpcap buffers in libc stdio and the pcap is
 * only visible after the daemon closes the file.
 *
 * Zero-length frames are valid: the drop path may legitimately see a
 * 0-byte frame from a hostile sender, and the forensic record must
 * include it (a pcap record with caplen=0 and len=0 is legal per the
 * pcap format). Short frames (1..13 bytes) are also written, even
 * though tcpdump will print them with a truncation marker — the point
 * is to preserve what happened, not what the analyzer expects.
 */

#define _GNU_SOURCE
#include "pcap_writer.h"

#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

struct pcap_writer {
    pcap_t        *pcap;
    pcap_dumper_t *dumper;
};

pcap_writer_t *pcap_writer_open(const char *path, int snaplen)
{
    if (!path || snaplen <= 0)
        return NULL;

    struct pcap_writer *w = calloc(1, sizeof(*w));
    if (!w)
        return NULL;

    w->pcap = pcap_open_dead(DLT_EN10MB, snaplen);
    if (!w->pcap) {
        free(w);
        return NULL;
    }

    w->dumper = pcap_dump_open(w->pcap, path);
    if (!w->dumper) {
        pcap_close(w->pcap);
        free(w);
        return NULL;
    }

    return w;
}

int pcap_writer_write(pcap_writer_t *w,
                      const void *pkt, uint32_t caplen, uint32_t wirelen)
{
    if (!w || !w->dumper)
        return -1;

    /* caplen must not exceed wirelen: caplen is by definition a
     * prefix of the wire frame. A malformed call with caplen > wirelen
     * is a bug in the caller, not a legitimate capture. */
    if (caplen > wirelen)
        return -1;

    /* If we're going to copy bytes, there must be bytes to copy. */
    if (caplen > 0 && !pkt)
        return -1;

    /*
     * pcap_pkthdr.ts is a struct timeval. libpcap does not timestamp
     * records on its own; the caller must supply the time.
     * gettimeofday() at the moment of the write is the closest we
     * can get to the drop time without a BPF-side timestamp.
     */
    struct pcap_pkthdr hdr;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    hdr.ts     = tv;
    hdr.caplen = caplen;
    hdr.len    = wirelen;

    /* pcap_dump with caplen == 0 and pkt == NULL is legal: it writes
     * a record header with caplen=0 and len=wirelen, and no data.
     * We pass pkt (possibly NULL) through unchanged. */
    pcap_dump((u_char *)w->dumper, &hdr, (const u_char *)pkt);

    /*
     * Flush after every write so the pcap is readable by tcpdump
     * while the daemon is running. Without this, libpcap buffers in
     * stdio and the file stays empty until pcap_dump_close().
     *
     * Cost: one fflush per dropped packet. For a forensic capture
     * that's the right trade — the operator wants to `tcpdump -r`
     * the file while the incident is in progress.
     */
    if (pcap_dump_flush(w->dumper) != 0)
        return -1;

    return 0;
}

void pcap_writer_close(pcap_writer_t *w)
{
    if (!w)
        return;

    if (w->dumper) {
        pcap_dump_flush(w->dumper);
        pcap_dump_close(w->dumper);
        w->dumper = NULL;
    }
    if (w->pcap) {
        pcap_close(w->pcap);
        w->pcap = NULL;
    }
    free(w);
}
