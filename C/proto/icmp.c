/* icmp.c
 *
 * $Id: pakvalupdate.c 1 2010-04-11 21:04:36 vijay mohan $
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

#include "../main.h"
#include "icmp.h"
#include "ip.h"
#include "../packet.h"

void
display_icmp(uint8_t **pak)
{
	struct icmphdr *icmp_hdr;

	icmp_hdr = (struct icmphdr *)*pak;

	ptree_append("Internet Control Message Protocol", NULL, STRING, 0, P_ICMP, 0);
	ptree_append("Type:", &icmp_hdr->type, UINT8, 1, P_ICMP, 0);
	ptree_append("Code:", &icmp_hdr->code, UINT8, 1, P_ICMP, 0);
	ptree_append("Checksum:", &icmp_hdr->checksum, UINT16_HEX, 1, P_ICMP, 0);
	ptree_append("Identifier:", &icmp_hdr->id, UINT16, 1, P_ICMP, 0);
	ptree_append("Sequence number:", &icmp_hdr->sequence, UINT16, 1, P_ICMP, 0);
	
	cur_pak_info.L5_off = 0;
	cur_pak_info.L4_proto = 0;
}

void
update_icmp(char *value)
{
	struct icmphdr *icmp_hdr;
	struct iphdr   *ip_hdr;

	ip_hdr   = (struct iphdr *)(fpak_curr_info->pak + cur_pak_info.L3_off);
	icmp_hdr = (struct icmphdr *)(fpak_curr_info->pak + cur_pak_info.L4_off);

        if (!strcmp(ptype,"Type:")) {
                pak_val_update(&icmp_hdr->type, value, UINT8);
        } else if (!strcmp(ptype,"Code:")) {
                pak_val_update(&icmp_hdr->code, value, UINT8);
	} else if (!strcmp(ptype,"Checksum:")) {
                pak_val_update(&icmp_hdr->checksum, value, UINT16_HEX);
        } else if (!strcmp(ptype,"Identifier:")) {
                pak_val_update(&icmp_hdr->id, value, UINT16D);
        } else if (!strcmp(ptype,"Sequence number:")) {
                pak_val_update(&icmp_hdr->sequence, value, UINT16D);
        } 
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = in_cksum(icmp_hdr, (ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4)));
}
