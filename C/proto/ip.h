/* ip.h
 *
 * $Id: ip.h 1 2010-04-11 21:04:36 vijay mohan $
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

#ifndef __IPV4_H__
#define __IPv4_H__

#include<stdint.h>

struct iphdr
{
    uint32_t ihl:4;
    uint32_t version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
    /*The options start here. */
};

/* IPv6 address */
struct inipv6_addr
  {
    union
      {
    uint8_t __u6_addr8[16];
    uint16_t __u6_addr16[8];
    uint32_t __u6_addr32[4];
      } __in6_u;
  };


struct ip6hdr {
    uint32_t  vtf;
    uint16_t  payload_length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    struct  inipv6_addr saddr;
    struct  inipv6_addr daddr;
    /*The options start here. */
};

struct sre {
	uint16_t af;
	uint8_t  offset;
	uint8_t  length;
	uint8_t  rinfo[0]; 

};

struct grehdr 
{
	uint16_t fandv;
	uint16_t protocol;
	uint16_t csum;
	uint16_t offset;
	uint32_t key;
	uint32_t seq_no;
	struct sre sre_hdr[0];
};


uint8_t
display_ip(uint8_t **pak, uint16_t l3_proto);

void
update_ip(char *value);

uint16_t 
ComputeChecksum(uint8_t *data, uint8_t len);

#endif
