/* tcp.c
 *
 * $Id: tcp.c 1 2010-04-11 21:04:36 vijay mohan $
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tcp.h"
#include <stdint.h>
#include "../main.h"
#include "../packet.h"

typedef struct v6_PseudoHeader{

	struct   inipv6_addr saddr;
	struct   inipv6_addr daddr;
	uint32_t tcp_length;
	uint8_t  zeros[3];
	uint8_t  next_hdr;

}v6_PseudoHeader;

unsigned short chksum_v6(void* buff, int len, struct inipv6_addr* src, struct inipv6_addr* dst,
                         uint16_t upproto)
{
	uint16_t check_sum = 0;
	struct tcphdr *tcp_hdr = (struct tcphdr *)buff;

	uint16_t header_len = sizeof(v6_PseudoHeader) + len;
	uint8_t *hdr = (uint8_t *)calloc(1, header_len);

	v6_PseudoHeader *pseudo_header = (v6_PseudoHeader *)hdr;

	memcpy(&pseudo_header->saddr, src, sizeof(struct inipv6_addr));
	memcpy(&pseudo_header->daddr, dst, sizeof(struct inipv6_addr));
	pseudo_header->tcp_length = ntohl(len);
	pseudo_header->next_hdr = upproto;

	tcp_hdr->check = 0;
	memcpy((hdr + sizeof(v6_PseudoHeader)), buff, len);
	
	check_sum = in_cksum((u_short *)hdr, header_len);

	free(hdr);

        return check_sum;	
	
}


typedef struct PseudoHeader{

        uint32_t source_ip;
        uint32_t dest_ip;
        uint8_t reserved;
        uint8_t protocol;
        uint16_t tcp_length;

}PseudoHeader;

uint16_t
ComputeTCPChecksum(struct tcphdr *tcp_header, struct iphdr *ip_header)
{
	uint16_t check_sum = 0;
        /*The TCP Checksum is calculated over the PseudoHeader + TCP header +Data*/

        /* Find the size of the TCP Header + Data */
        uint16_t segment_len = ntohs(ip_header->tot_len) - ip_header->ihl*4;
        /* Total length over which TCP checksum will be computed */
        uint16_t header_len = sizeof(PseudoHeader) + segment_len;

        /* Allocate the memory */

        uint8_t *hdr = (uint8_t *)malloc(header_len);

        /* Fill in the pseudo header first */

        PseudoHeader *pseudo_header = (PseudoHeader *)hdr;

        pseudo_header->source_ip = ip_header->saddr;
        pseudo_header->dest_ip = ip_header->daddr;
        pseudo_header->reserved = 0;
        pseudo_header->protocol = ip_header->protocol;
        pseudo_header->tcp_length = htons(segment_len);


	tcp_header->check = 0;
        /* Now copy TCP + data*/

        memcpy((hdr + sizeof(PseudoHeader)), (void *)tcp_header, segment_len);


        /* Calculate the Checksum */

        check_sum = in_cksum((u_short *)hdr, header_len);

        /* Free the PseudoHeader */
        free(hdr);

        return check_sum;

}

void
display_tcp(uint8_t **pak)
{
	struct tcphdr *tcp_hdr;
	uint8_t i8;

	tcp_hdr = (struct tcphdr *)*pak;

	ptree_append ("Transmission Control Protocol", NULL, STRING, 0, P_TCP, 0);
	ptree_append("Source Port:", &tcp_hdr->source, UINT16, 1, P_TCP, 0);
	ptree_append("Destination Port:", &tcp_hdr->dest, UINT16, 1, P_TCP, 0);
	ptree_append("Sequence number:", &tcp_hdr->seq, UINT32, 1, P_TCP, 0);
	ptree_append("Acknowledgement number:", &tcp_hdr->ack_seq, UINT32, 1, P_TCP, 0);
	i8 = tcp_hdr->doff;
	ptree_append("Data offset:", &i8, UINT8, 1, P_TCP, 0);
	i8 = tcp_hdr->res1;
	ptree_append("Reserved:", &i8, UINT8_HEX_1, 1, P_TCP, 0);
	i8 = (uint8_t)*(((uint8_t *)&tcp_hdr->ack_seq) + 5);
	ptree_append("Flags:", &i8, UINT8_HEX_2, 1, P_TCP, 0);
	i8 = tcp_hdr->cwr;
	ptree_append("Congestion Window Reduced (CWR):", &i8, UINT8, 2, P_TCP, 0);
	i8 = tcp_hdr->ece;
	ptree_append("ECN-Echo:", &i8, UINT8, 2, P_TCP, 0);
	i8 = tcp_hdr->urg;
	ptree_append("Urgent:", &i8, UINT8, 2, P_TCP, 0);
	i8 = tcp_hdr->ack;
	ptree_append("Acknowledgement:", &i8, UINT8, 2, P_TCP, 0);
	i8 = tcp_hdr->psh;
	ptree_append("Push:", &i8, UINT8, 2, P_TCP, 0);
	i8 = tcp_hdr->rst;
	ptree_append("Reset:", &i8, UINT8, 2, P_TCP, 0);
	i8 = tcp_hdr->syn;
	ptree_append("syn:", &i8, UINT8, 2, P_TCP, 0);
	i8 = tcp_hdr->fin;
	ptree_append("Fin:", &i8, UINT8, 2, P_TCP, 0);
	ptree_append("Window size:", &tcp_hdr->window, UINT16, 1, P_TCP, 0);
	ptree_append("Checksum:", &tcp_hdr->check, UINT16_HEX, 1, P_TCP, 0);
	ptree_append("Urgent pointer:", &tcp_hdr->urg_ptr, UINT16, 1, P_TCP, 0);

	cur_pak_info.src_port = ntohs(tcp_hdr->source);
	cur_pak_info.dst_port = ntohs(tcp_hdr->dest);

	*pak += tcp_hdr->doff * 4;

}

void
update_tcp(char *value)
{
	struct tcphdr *tcp_hdr;
	struct iphdr *ip_hdr;
	struct ip6hdr *ip6_hdr;
	uint8_t i8;
	uint8_t *p8;

	tcp_hdr = (struct tcphdr *)(fpak_curr_info->pak + cur_pak_info.L4_off);

	if (!strcmp(ptype,"Source Port:")) {
		pak_val_update(&tcp_hdr->source, value, UINT16D);	
        } else if (!strcmp(ptype,"Destination port:")) {
		pak_val_update(&tcp_hdr->dest, value, UINT16D);
	} else if (!strcmp(ptype,"Sequence number:")) {
		pak_val_update(&tcp_hdr->seq, value, UINT32D);
        } else if (!strcmp(ptype,"Acknowledgement number:")) {
		pak_val_update(&tcp_hdr->ack_seq, value, UINT32D);
        } else if (!strcmp(ptype,"Data offset:")) {
		tcp_hdr->doff = atoi(value);
        } else if (!strcmp(ptype,"Reserved:")) {
		pak_val_update(&i8, value, UINT8_HEX_2);
		tcp_hdr->res1 = i8;
        } else if (!strcmp(ptype,"Flags:")) {
		p8 = (((uint8_t *)&tcp_hdr->ack_seq) + 5);
		i8 = (uint8_t)*(((uint8_t *)&tcp_hdr->ack_seq) + 5);
		i8 = pak_set_bits_uint8_hex(i8, 7, 8, value);
		*p8 = i8;
        } else if (!strcmp(ptype,"Congestion Window Reduced (CWR):")) {
		tcp_hdr->cwr = atoi(value);
        } else if (!strcmp(ptype,"ECN-Echo:")) {
		tcp_hdr->ece = atoi(value);
        } else if (!strcmp(ptype,"Urgent:")) {
		tcp_hdr->urg = atoi(value);
        } else if (!strcmp(ptype,"Acknowledgement:")) {
		tcp_hdr->ack = atoi(value);
        } else if (!strcmp(ptype,"Push:")) {
		tcp_hdr->psh = atoi(value);
        } else if (!strcmp(ptype,"Reset:")) {
		tcp_hdr->rst = atoi(value);
        } else if (!strcmp(ptype,"syn:")) {
		tcp_hdr->syn = atoi(value);
        } else if (!strcmp(ptype,"Fin:")) {
		tcp_hdr->fin = atoi(value);
        } else if (!strcmp(ptype,"Window size:")) {
		pak_val_update(&tcp_hdr->window, value, UINT16D);
        } else if (!strcmp(ptype,"Checksum:")) {
		pak_val_update(&tcp_hdr->check, value, UINT16_HEX);
        } else if (!strcmp(ptype,"Urgent pointer:")) {
		pak_val_update(&tcp_hdr->urg_ptr, value, UINT16D);
        }
	if (cur_pak_info.L3_proto == 0x0800) {
		ip_hdr = (struct iphdr *)(fpak_curr_info->pak + cur_pak_info.L3_off);
		tcp_hdr->check = ComputeTCPChecksum(tcp_hdr, ip_hdr);
	} else if (cur_pak_info.L3_proto == 0x86DD) {
		ip6_hdr = (struct ip6hdr *)(fpak_curr_info->pak + cur_pak_info.L3_off);
		tcp_hdr->check = 0;
		tcp_hdr->check = chksum_v6 ((void *)tcp_hdr, ntohs(ip6_hdr->payload_length), &(ip6_hdr->saddr), &(ip6_hdr->daddr), ip6_hdr->next_header);
	}
}
