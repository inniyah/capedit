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
add_mtag (struct pak_file_info *fpak_info, uint16_t label, uint16_t exp, uint16_t stack, uint16_t ttl)
{
        struct ethhdr 	   *eth_hdr;
        struct vlan_802_1q *vlan_hdr;
	struct mplshdr     *mpls_temp_hdr;
	struct mplshdr     mpls_hdr;
        uint8_t *pak      = NULL;
        uint8_t *new_pak  = NULL;
	uint8_t *pak_temp = NULL;
        uint16_t protocol;
	uint16_t hdrs_len = 0;
	uint8_t  vlan_present = 0;
	uint8_t  mpls_present = 0;
	uint32_t *pv32;
        
        if (fpak_info->mem_alloc == 0) {
                fseek(p->rfile,fpak_info->offset,0);
                p->buffer = p->base;
                pcap_offline_read(p,1);
                fpak_info->pak = p->buffer;
                fpak_info->pak_len = p->cap_len;
        }
        pak_temp = pak = (uint8_t *)fpak_info->pak;
        eth_hdr  = (struct ethhdr *)pak;
	protocol = eth_hdr->h_proto;
	hdrs_len += sizeof(struct ethhdr); 	
	pak_temp = pak + sizeof(struct ethhdr);
	pv32  = (uint32_t *)&mpls_hdr;	

	*pv32 = htonl(setbits(ntohl(*pv32), 31, 20, label));
	*pv32 = htonl(setbits(ntohl(*pv32), 11, 3, exp));
	*pv32 = htonl(setbits(ntohl(*pv32), 8, 1, stack));
	*pv32 = htonl(setbits(ntohl(*pv32), 7, 8, ttl));

	for (;protocol == 0x0081;) { //vlan
		vlan_hdr = (struct vlan_802_1q *)pak_temp;
		protocol = vlan_hdr->protocol;
		hdrs_len += sizeof(struct vlan_802_1q);
		pak_temp += sizeof(struct vlan_802_1q);	
		vlan_present =1;
	}
        for (;protocol == 0x4788;) { //MPLS
                mpls_temp_hdr = (struct mplshdr *)pak_temp;
                hdrs_len += sizeof(struct mplshdr);
                pak_temp += sizeof(struct mplshdr);
		mpls_present = 1;
		if (pak_get_bits_uint32(*(uint32_t *)mpls_temp_hdr, 8, 1) == 1) {
			*(uint32_t *)mpls_temp_hdr = htonl(setbits(ntohl(*(uint32_t *)mpls_temp_hdr), 8, 1, 0));;
			break;
		}
        }
        if ((protocol != 0x0008) && (mpls_present != 1)) {
                return;
        }	
	if (vlan_present == 1) {
		vlan_hdr->protocol = 0x4788;
	} else {
		eth_hdr->h_proto = 0x4788; /*MPLS*/
	}
        new_pak = (uint8_t *)malloc(fpak_info->pak_hdr.caplen + sizeof(struct mplshdr));
        memcpy(new_pak, pak, hdrs_len);
        memcpy((new_pak + hdrs_len), (uint8_t *)&mpls_hdr, sizeof(struct mplshdr));
        memcpy((new_pak + hdrs_len + sizeof(struct mplshdr)),
                pak + hdrs_len, (fpak_info->pak_hdr.caplen - hdrs_len));
        if (fpak_info->mem_alloc == 1) {
                free(fpak_info->pak);
        }
        fpak_info->mem_alloc = 1;
        fpak_info->pak = new_pak;
        fpak_info->pak_hdr.caplen += sizeof(struct mplshdr);
        fpak_info->pak_len = fpak_info->pak_hdr.len = fpak_info->pak_hdr.caplen;

}

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
