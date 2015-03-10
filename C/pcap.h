/* pcap.h
 *
 * $Id: pcap.h 1 2010-04-11 21:04:36 vijay mohan $
 *
 * PacketSquare-capedit - Pcap Edit & Replay Tool
 * By vijay mohan <vijaymohan@packetsquare.com>
 * Copyright 2010 vijay mohan
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef pcap_h
#define pcap_h

#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#include <stdlib.h>

#define TCPDUMP_MAGIC           0xa1b2c3d4

#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

#define __packed

typedef struct pcap pcap_t;

struct pcap_file_header {
        uint32_t magic;
        uint16_t version_major;
        uint16_t version_minor;
        uint32_t thiszone;     /* gmt to local correction */
        uint32_t sigfigs;    /* accuracy of timestamps */
        uint32_t snaplen;    /* max length saved portion of each pkt */
        uint32_t linktype;   /* data link type (LINKTYPE_*) */
} __packed;

struct pcap_pkthdr {
        struct timeval ts;      /* time stamp */
        uint32_t caplen;     /* length of portion present */
        uint32_t len;        /* length this packet (off wire) */
} __packed;

struct pcap {
	FILE *rfile;
	struct pcap_file_header cap_file_hdr;
	struct pcap_pkthdr pak_hdr;
	uint8_t *base;
	uint8_t *buffer;
	uint32_t bufsize;
	uint16_t cap_len;
};

void
free_pcapt(pcap_t *);

#endif

