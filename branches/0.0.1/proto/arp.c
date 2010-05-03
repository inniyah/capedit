/* arp.c
 *
 * $Id: arp.c 1 2010-04-11 21:04:36 vijay mohan $
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
#include "arp.h"
#include "../packet.h"

void
display_arp(uint8_t **pak)
{
	struct arphdr *arp_hdr;

	arp_hdr = (struct arphdr *)*pak;

	ptree_append ("Address Resoluton Protocol", NULL, STRING, 0, P_ARP, 0);
	ptree_append("Hardware type:", &arp_hdr->ar_hrd, UINT16_HEX, 1, P_ARP, 0);
	ptree_append("Protocol type:", &arp_hdr->ar_pro, UINT16_HEX, 1, P_ARP, 0);
	ptree_append("Hardware size:", &arp_hdr->ar_hln, UINT8, 1, P_ARP, 0);
	ptree_append("Protocol size:", &arp_hdr->ar_pln, UINT8, 1, P_ARP, 0);
	ptree_append("Opcode:", &arp_hdr->ar_op, UINT16_HEX, 1, P_ARP, 0);
	ptree_append("Sender MAC address:", &arp_hdr->ar_sha, MAC, 1, P_ARP, 0);
	ptree_append("Sender IP address:", &arp_hdr->ar_sip, IPV4_ADDR, 1, P_ARP, 0);
	ptree_append("Target MAC address:", &arp_hdr->ar_tha, MAC, 1, P_ARP, 0);
	ptree_append("Target IP address:", &arp_hdr->ar_tip, IPV4_ADDR, 1, P_ARP, 0);

	cur_pak_info.proto  = 0;
	cur_pak_info.L4_off = 0;
	cur_pak_info.L4_proto = 0;

}

void
update_arp(char *value)
{
	struct arphdr *arp_hdr;

	arp_hdr = (struct arphdr *)(fpak_curr_info->pak + cur_pak_info.L3_off);

        if (!strcmp(ptype,"Hardware type:")) {
                pak_val_update(&arp_hdr->ar_hrd, value, UINT16_HEX);
        } else if (!strcmp(ptype,"Protocol type:")) {
                pak_val_update(&arp_hdr->ar_pro, value, UINT16_HEX);
        } else if (!strcmp(ptype,"Hardware size:")) {
                pak_val_update(&arp_hdr->ar_hln, value, UINT8);
        } else if (!strcmp(ptype,"Protocol size:")) {
                pak_val_update(&arp_hdr->ar_pln, value, UINT8);
        } else if (!strcmp(ptype,"Opcode:")) {
                pak_val_update(&arp_hdr->ar_op, value, UINT16_HEX);
        } else if (!strcmp(ptype,"Sender MAC address:")) {
                pak_val_update(&arp_hdr->ar_sha, value, MAC);
        } else if (!strcmp(ptype,"Sender IP address:")) {
                pak_val_update(&arp_hdr->ar_sip, value, IPV4_ADDR);
        } else if (!strcmp(ptype,"Target MAC address:")) {
                pak_val_update(&arp_hdr->ar_tha, value, MAC);
        } else if (!strcmp(ptype,"Target IP address:")) {
                pak_val_update(&arp_hdr->ar_tip, value, IPV4_ADDR);
        }
}
