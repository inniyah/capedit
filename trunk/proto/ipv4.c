/* ipv4.c
 *
 * $Id: ipv4.c 1 2010-04-11 21:04:36 vijay mohan $
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

#include<stdio.h>
#include<stdint.h>
#include"../main.h"
#include<stdlib.h>
#include"../pakvalupdate.h"
#include "../packet.h"
#include "tcp.h"
#include "udp.h"

u_short
in_cksum(const u_short *addr, register u_int len)
{
        int nleft = len;
        const u_short *w = addr;
        u_short answer;
        int sum = 0;

        /*
 *  *          *  Our algorithm is simple, using a 32 bit accumulator (sum),
 *   *                   *  we add sequential 16 bit words to it, and at the end, fold
 *    *                            *  back all the carry bits from the top 16 bits into the lower
 *     *                                     *  16 bits.
 *      *                                              */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }
        if (nleft == 1)
                sum += htons(*(u_char *)w<<8);

        /*
 *  *          * add back carry outs from top 16 bits to low 16 bits
 *   *                   */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return (answer);
}

uint8_t
display_ipv4(uint8_t **pak)
{
	struct iphdr *ip_hdr;
	uint32_t temp;

	ip_hdr = (struct iphdr *)*pak;
	ptree_append ("Internet Protocol(IPv4)",NULL,STRING,0, P_IPV4, 0);	
	temp = ip_hdr->version;
	ptree_append ("Version:",&temp,UINT8,1, P_IPV4, 0);
	temp = ip_hdr->ihl;
        ptree_append("Header length:",&temp,UINT8,1, P_IPV4, 0);
        ptree_append("Tos:",&ip_hdr->tos,UINT8,1, P_IPV4, 0);
        ptree_append("Total length:",&ip_hdr->tot_len,UINT16,1, P_IPV4, 0);
        ptree_append("Identification:",&ip_hdr->id,UINT16_HEX,1, P_IPV4, 0);
	temp = pak_get_bits_uint16(ip_hdr->frag_off, 15, 3);
	ptree_append("Flags:", &temp, UINT8_HEX_1 ,1, P_IPV4, 0);
	temp = pak_get_bits_uint16(ip_hdr->frag_off, 15, 1);
	ptree_append("Reserved bit:", &temp, UINT8, 2, P_IPV4, 0);
        temp = pak_get_bits_uint16(ip_hdr->frag_off, 14, 1);
        ptree_append("Don't fragment:", &temp, UINT8, 2, P_IPV4, 0);
        temp = pak_get_bits_uint16(ip_hdr->frag_off, 13, 1);
        ptree_append("More fragments:", &temp, UINT8, 2, P_IPV4, 0);
	temp = pak_get_bits_uint16(ip_hdr->frag_off, 12, 13);
        ptree_append("Fragment offset:",&temp,UINT16HD,1, P_IPV4, 0);
        ptree_append("Time to live:",&ip_hdr->ttl,UINT8,1, P_IPV4, 0);
        ptree_append("Protocol:",&ip_hdr->protocol,UINT8,1, P_IPV4, 0);
        ptree_append("Header checksum:",&ip_hdr->check,UINT16_HEX,1, P_IPV4, 0);
        ptree_append("Source IP:",&ip_hdr->saddr,IPV4_ADDR,1, P_IPV4, 0);
        ptree_append("Destination IP:",&ip_hdr->daddr,IPV4_ADDR,1, P_IPV4, 0);

	cur_pak_info.src_ip = ip_hdr->saddr;
	cur_pak_info.dst_ip = ip_hdr->daddr;
	cur_pak_info.proto  = ip_hdr->protocol;
	*pak += (ip_hdr->ihl * 4);
	cur_pak_info.L4_off = cur_pak_info.L3_off + (ip_hdr->ihl * 4);
	cur_pak_info.L4_proto = ip_hdr->protocol;
	return cur_pak_info.L4_proto;
}

void update_ipv4(char *value)
{
	struct iphdr *ip_hdr;
	uint16_t i16_1, i16_2;
        struct tcphdr *tcp_hdr;
        struct udphdr *udp_hdr;
	
	ip_hdr = (struct iphdr *)(fpak_curr_info->pak + cur_pak_info.L3_off);
	if (!strcmp(ptype,"Version:")) {
		ip_hdr->version = atoi(value);
	} else if (!strcmp(ptype,"Header length:")) {
		ip_hdr->ihl = atoi(value);
	} else if (!strcmp(ptype,"Tos:")) {
      		pak_val_update(&ip_hdr->tos, value, UINT8D); 
        } else if (!strcmp(ptype,"Total length:")) {
       		pak_val_update(&ip_hdr->tot_len, value, UINT16D); 
        } else if (!strcmp(ptype,"Identification:")) {
       		pak_val_update(&ip_hdr->id, value, UINT16_HEX); 
        } else if (!strcmp(ptype,"Flags:")) {
		ip_hdr->frag_off = pak_set_bits_uint16_hex(ip_hdr->frag_off, 15, 3, value);
        } else if (!strcmp(ptype,"Reserved bit:")) {
		 ip_hdr->frag_off = pak_set_bits_uint16(ip_hdr->frag_off, 15, 1, value);
        } else if (!strcmp(ptype,"Don't fragment:")) {
       		ip_hdr->frag_off = pak_set_bits_uint16(ip_hdr->frag_off, 14, 1, value); 
        } else if (!strcmp(ptype,"More fragments:")) {
        	ip_hdr->frag_off = pak_set_bits_uint16(ip_hdr->frag_off, 13, 1, value);
        } else if (!strcmp(ptype,"Fragment offset:")) {
		ip_hdr->frag_off = pak_set_bits_uint16D(ip_hdr->frag_off, 12, 13, value);
        } else if (!strcmp(ptype,"Time to live:")) {
        	pak_val_update(&ip_hdr->ttl, value, UINT8);
        } else if (!strcmp(ptype,"Protocol:")) {
        	pak_val_update(&ip_hdr->protocol, value, UINT8);
        } else if (!strcmp(ptype,"Header checksum:")) {
        	pak_val_update(&ip_hdr->check, value, UINT16_HEX);
        } else if (!strcmp(ptype,"Source IP:")) {
       		pak_val_update(&ip_hdr->saddr, value, IPV4_ADDR); 
        } else if (!strcmp(ptype,"Destination IP:")) {
        	pak_val_update(&ip_hdr->daddr, value, IPV4_ADDR);
        }
	ip_hdr->check = 0;
	ip_hdr->check = in_cksum((u_short *)ip_hdr, ip_hdr->ihl*4);
	if (ip_hdr->protocol == 0x11) {
		udp_hdr = (struct udphdr *)(fpak_curr_info->pak + cur_pak_info.L4_off);
		udp_hdr->check = ComputeUDPChecksum(udp_hdr, ip_hdr);
	} else if (ip_hdr->protocol == 0x06) {
		tcp_hdr = (struct tcphdr *)(fpak_curr_info->pak + cur_pak_info.L4_off);
		tcp_hdr->check = ComputeTCPChecksum(tcp_hdr, ip_hdr);
	}

}


