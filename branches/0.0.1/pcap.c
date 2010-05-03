/* pcap.c
 *
 * $Id: pcap.c 1 2010-04-11 21:04:36 vijay mohan $
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

#include "pcap.h"
#include <string.h>
#include "error.h"

int
pcap_read_next_pak(pcap_t *p,struct pcap_pkthdr *hdr, uint8_t *buf, uint8_t buflen)
{
	struct pcap_pkthdr h;
	FILE *fp = p->rfile;
        size_t amt_read;

        amt_read = fread(&h, 1, sizeof(h), fp);
        if (amt_read != sizeof(h)) {
                if (ferror(fp)) {
                        sprintf(err_msg, "error reading dump file: %s\n",strerror(errno));
			error_top_level();
			return (-1);
                } else {
			if (amt_read != 0) {
                        	sprintf(err_msg,"truncated dump file; tried to read %lu file header bytes, only got %lu\n",
                            		(unsigned long)sizeof(h),
                            		(unsigned long)amt_read);
				error_top_level();
				return(-1);
			}
			return (1);
                }
        }
	memcpy((void *)&p->pak_hdr, (void *)&h, sizeof(struct pcap_pkthdr));
	hdr->caplen = h.caplen;
	hdr->len = h.len;
	hdr->ts.tv_sec = h.ts.tv_sec;
	hdr->ts.tv_usec = h.ts.tv_usec;

	p->cap_len = h.caplen;

	amt_read = fread((char *)buf, 1, h.caplen, fp);
	if (amt_read != hdr->caplen) {
		if (ferror(fp)) {
			sprintf(err_msg, "error reading dump file: %si\n",
			strerror(errno));
			error_top_level();
			return (-1);
		} else {
			if (amt_read != 0) {
				sprintf(err_msg, "truncated dump file; tried to read %u captured bytes, only got %lu\n",
					hdr->caplen, (unsigned long)amt_read);
				error_top_level();
				return (-1);
			}
			return (1);
		}
	} 
	return (0);
}

int
pcap_offline_read(pcap_t *p, uint32_t cnt)
{
        int status = 0;
        struct pcap_pkthdr h;
	int n = 0;

        while(status == 0)
        {
                status = pcap_read_next_pak(p, &h, p->buffer, p->bufsize);
                if (status) {
                        if (status == 1)
                                return (0);
                        return (0);
                }
		if (++n >= cnt && cnt > 0)
			break;
        }

	return (n);
}


pcap_t *
pcap_open(const char *fname)
{
	FILE *fp;
	struct pcap_file_header hdr;
	size_t amt_read;
	uint32_t magic;
	pcap_t *p;


	fp = fopen(fname, "rb");
	if (fp == NULL) {
		sprintf(err_msg, "error opening pcap file - %s\n",fname);
		return (NULL);
	}
	p = (pcap_t *)calloc(1,sizeof(pcap_t));
	if (p == NULL) {
		printf("pcap_t malloc failed");
		exit(-1);
	}
	amt_read = fread((char *)&hdr, 1, sizeof(hdr), fp);
        if (amt_read != sizeof(hdr)) {
                if (ferror(fp)) {
                        sprintf(err_msg, "error reading dump file: %s\n",fname);
			strerror(errno);
			error_top_level();
                } else {
                        sprintf(err_msg, "truncated dump file; tried to read %lu file header bytes, only got %lu\n",
                            (unsigned long)sizeof(hdr),
                            (unsigned long)amt_read);
			error_top_level();
                }
                //goto bad;
        }
	memcpy((void *)&p->cap_file_hdr, (void *)&hdr, sizeof(struct pcap_file_header));
	magic = hdr.magic;
	if (magic != TCPDUMP_MAGIC)
	{
		sprintf(err_msg, "Not a TCPDUMP STANDARD FORMAT file\n");
		error_top_level();
		return (NULL);
	}

        if (hdr.version_major < PCAP_VERSION_MAJOR) {
                sprintf(err_msg, "archaic file format\n");
                //goto bad;
                error_top_level();
                return (NULL);
        }
	p->rfile = fp;
	p->bufsize = hdr.snaplen + sizeof(struct pcap_pkthdr);
	p->base = (uint8_t *)calloc(1,hdr.snaplen + sizeof(struct pcap_pkthdr) + sizeof(uint32_t));
	p->buffer = p->base; //- 2;
	
	return (p);
	
}

void free_pcapt(pcap_t *p)
{
	close(p->rfile);
	free(p->base);
	free(p);			
}
