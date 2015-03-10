/* udp.c
 *
 * $Id: udp.c 1 2010-04-11 21:04:36 vijay mohan $
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ip.h"
#include"../main.h"
#include "../packet.h"
#include "udp.h"

typedef struct PseudoHeader{

        unsigned long int source_ip;
        unsigned long int dest_ip;
        unsigned char reserved;
        unsigned char protocol;
        unsigned short int udp_length;

}PseudoHeader;

uint16_t
ComputeUDPChecksum(struct udphdr *udp_header, struct iphdr *ip_header)
{
        uint16_t check_sum = 0;
        /*The TCP Checksum is calculated over the PseudoHeader + TCP header +Data*/

        /* Find the size of the UDP Header + Data */
        int segment_len = ntohs(ip_header->tot_len) - ip_header->ihl*4;

        /* Total length over which UDP checksum will be computed */
        int header_len = sizeof(PseudoHeader) + segment_len;

        /* Allocate the memory */

        unsigned char *hdr = (unsigned char *)malloc(header_len);

        /* Fill in the pseudo header first */

        PseudoHeader *pseudo_header = (PseudoHeader *)hdr;

        pseudo_header->source_ip = ip_header->saddr;
        pseudo_header->dest_ip = ip_header->daddr;
        pseudo_header->reserved = 0;
        pseudo_header->protocol = ip_header->protocol;
        pseudo_header->udp_length = htons(segment_len);


        udp_header->check = 0;
        /* Now copy TCP + data*/

        memcpy((hdr + sizeof(PseudoHeader)), (void *)udp_header, segment_len);


        /* Calculate the Checksum */

        check_sum = in_cksum((u_short *)hdr, header_len);

        /* Free the PseudoHeader */
        free(hdr);

        return check_sum;
}

uint16_t
display_udp(uint8_t **pak)
{
	struct udphdr *udp_hdr;

	udp_hdr = (struct udphdr *)*pak;

	ptree_append("User Datagram Protocol", NULL, STRING, 0, P_UDP, 0);
	ptree_append("Source Port:", &udp_hdr->source, UINT16, 1, P_UDP, 0);
	ptree_append("Destination Port:",&udp_hdr->dest, UINT16, 1, P_UDP, 0);
	ptree_append("Length:",&udp_hdr->len,UINT16,1, P_UDP, 0);
	ptree_append("Checksum:",&udp_hdr->check,UINT16_HEX,1, P_UDP, 0);

	cur_pak_info.src_port = ntohs(udp_hdr->source);
	cur_pak_info.dst_port = ntohs(udp_hdr->dest);

	*pak += sizeof(struct udphdr);

}

void
update_udp(char *value)
{
	struct udphdr *udp_hdr;
	struct iphdr  *ip_hdr;
	struct ip6hdr *ip6_hdr;

	ip_hdr  = (struct iphdr *)(fpak_curr_info->pak + cur_pak_info.L3_off);
	udp_hdr = (struct udphdr *)(fpak_curr_info->pak + cur_pak_info.L4_off);

	if (!strcmp(ptype,"Source Port:")) {
		pak_val_update(&udp_hdr->source, value, UINT16D);
        } else if (!strcmp(ptype,"Destination Port:")) {
		pak_val_update(&udp_hdr->dest, value, UINT16D);
        } else if (!strcmp(ptype,"Length:")) {
		pak_val_update(&udp_hdr->len, value, UINT16D);
        } else if (!strcmp(ptype,"Checksum:")) {
		pak_val_update(&udp_hdr->check, value, UINT16_HEX);
	}
        if (cur_pak_info.L3_proto == 0x0800) {
                ip_hdr = (struct iphdr *)(fpak_curr_info->pak + cur_pak_info.L3_off);
                udp_hdr->check = ComputeTCPChecksum(udp_hdr, ip_hdr);
        } else if (cur_pak_info.L3_proto == 0x86DD) {
                ip6_hdr = (struct ip6hdr *)(fpak_curr_info->pak + cur_pak_info.L3_off);
                udp_hdr->check = 0;
                udp_hdr->check = chksum_v6 ((void *)udp_hdr, ntohs(ip6_hdr->payload_length), &(ip6_hdr->saddr), &(ip6_hdr->daddr), ip6_hdr->next_header);
        }
}
