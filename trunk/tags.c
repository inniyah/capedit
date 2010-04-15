/* tags.c
 *
 * $Id: tags.c 1 2010-04-14 23:50:30 vijay mohan $
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

#include <string.h>
#include "main.h"
#include "proto/ethernet.h"


uint8_t
add_vtag(struct pak_file_info *fpak_info, uint16_t priority, uint16_t cfi, uint16_t id)
{
	struct ethhdr *eth_hdr;
	struct vlan_802_1q vlan_hdr;
	uint8_t *pak     = NULL;
	uint8_t *new_pak = NULL;
	uint16_t protocol;
	uint16_t *pv16;
	
        if (fpak_info->mem_alloc == 0) {
                fseek(p->rfile,fpak_info->offset,0);
                p->buffer = p->base;
                pcap_offline_read(p,1);
                fpak_info->pak = p->buffer;
                fpak_info->pak_len = p->cap_len;
        }
        pak = (uint8_t *)fpak_info->pak;
        eth_hdr = (struct ethhdr *)pak;

	/*if (eth_hdr->h_proto == 0x0081) {
		return;
	}*/

	pv16  = (uint16_t *)&vlan_hdr;
	*pv16 = htons(setbits(ntohs(*pv16), 15, 3, priority));
	*pv16 = htons(setbits(ntohs(*pv16), 12, 1, cfi));
	*pv16 = htons(setbits(ntohs(*pv16), 11, 12, id));
	vlan_hdr.protocol = eth_hdr->h_proto;
	eth_hdr->h_proto = htons(0x8100);

	new_pak = (uint8_t *)malloc(fpak_info->pak_hdr.caplen + sizeof(struct vlan_802_1q));
	memcpy(new_pak, pak, sizeof(struct ethhdr));
	memcpy((new_pak + sizeof(struct ethhdr)), (uint8_t *)&vlan_hdr, sizeof(struct vlan_802_1q));
	memcpy((new_pak + sizeof(struct ethhdr) + sizeof(struct vlan_802_1q)), 
		(pak + sizeof(struct ethhdr)), (fpak_info->pak_hdr.caplen - sizeof(struct ethhdr)));
	if (fpak_info->mem_alloc == 1) {
		free(fpak_info->pak);
	}
	fpak_info->mem_alloc = 1;
	fpak_info->pak = new_pak;
	fpak_info->pak_hdr.caplen += sizeof(struct vlan_802_1q);
	fpak_info->pak_len = fpak_info->pak_hdr.len = fpak_info->pak_hdr.caplen;
}
