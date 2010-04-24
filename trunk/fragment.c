/* fragment.c
 *
 * $Id: fragment.c 1 2010-04-12 19:10:40 vijay mohan $
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
#include "proto/ethernet.h"
#include "proto/ip.h"
#include "fragment.h"
#include "pcap.h"

void
frag_pak (struct pak_file_info *fpak_info, uint16_t size)
{
	void *pak = NULL;
	uint8_t *new_pak = NULL;
	uint8_t *data = NULL;
	uint16_t data_len = 0;
	uint16_t hdrs_len = 0;
	uint16_t pad = 0;
	uint16_t ip_offset = 0;
	uint16_t data_offset = 0;
	struct ethhdr *eth_hdr;
	struct vlan_802_1q *vlan_hdr;
	struct iphdr  *ip_hdr;
	struct iphdr *ip_hdr_new;
	uint16_t protocol;	
	struct pak_file_info *temp_fpak_info;
	struct pak_file_info *last, *temp_fpak_prev;

	
	if (fpak_info->mem_alloc == 0) {
		fseek(p->rfile,fpak_info->offset,0);
		p->buffer = p->base;
		pcap_offline_read(p,1);
		fpak_info->pak = p->buffer;
		fpak_info->pak_len = p->cap_len;
	}
	pak = fpak_info->pak;
	eth_hdr = (struct ethhdr *)pak;
	protocol = ntohs(eth_hdr->h_proto);
	pak += sizeof(struct ethhdr);
	hdrs_len += sizeof(struct ethhdr);
        for (;protocol == 0x8100;) {
                vlan_hdr = (struct vlan_802_1q *)pak;
                protocol = ntohs(vlan_hdr->protocol);
                pak += sizeof(struct vlan_802_1q);
		hdrs_len += sizeof(struct vlan_802_1q);
        }
        for (;protocol == 0x8847;) {
		hdrs_len += sizeof(struct mplshdr);
                if (pak_get_bits_uint32(*(uint32_t *)pak, 8, 1) == 1) {
                        protocol = 0x0800;
			pak += sizeof(struct mplshdr);
                        break;
                }
		pak += sizeof(struct mplshdr);
        }
        if (protocol == 0x0800) { 
		ip_hdr = (struct iphdr *)pak;
		data_len = ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4);
		pak += (ip_hdr->ihl * 4);
		ip_offset = hdrs_len;
		hdrs_len += (ip_hdr->ihl * 4);
		data = (uint8_t *)pak; 
		if (data_len > size) {
			while (data_offset < data_len) {
				temp_fpak_info = (struct pak_file_info *)malloc(sizeof(struct pak_file_info));
				temp_fpak_info->pak_no = 0;	
				temp_fpak_info->offset = 0;
				temp_fpak_info->mem_alloc = 1;
				memcpy((void *)&temp_fpak_info->pak_hdr, (void *)&fpak_info->pak_hdr, sizeof(struct pcap_pkthdr));
				new_pak = (uint8_t *)malloc(hdrs_len + size);
				temp_fpak_info->pak = new_pak;
				memcpy(new_pak, (uint8_t *)eth_hdr, hdrs_len);
				memcpy((new_pak + hdrs_len), (data + data_offset), size);
				temp_fpak_info->pak_hdr.caplen = temp_fpak_info->pak_hdr.len = temp_fpak_info->pak_len = (hdrs_len + size);
				ip_hdr_new = (struct iphdr *)(new_pak + ip_offset);
				ip_hdr_new->tot_len = htons((ip_hdr->ihl * 4) + size);
				ip_hdr_new->frag_off = 0;
				ip_hdr_new->frag_off = htons(setbits(ntohs(ip_hdr_new->frag_off), 12, 13, (data_offset / 8)));
				ip_hdr_new->frag_off |= htons(setbits(ntohs(ip_hdr->frag_off), 13, 1, 1));
				if (data_offset == 0) {
					last = fpak_info->next;
					fpak_info->prev->next = temp_fpak_info; 
					temp_fpak_info->prev = fpak_info->prev;
					temp_fpak_info->next = last; 
				} else {
					temp_fpak_info->prev = temp_fpak_prev;
					temp_fpak_prev->next = temp_fpak_info;
					temp_fpak_info->next = last; 
					if (last != NULL) {
						last->prev = temp_fpak_info;
					}
				}

				data_offset += size;
				if (data_offset >= data_len) {
					ip_hdr_new->frag_off &= 0xFFDF;
					pad = data_offset - data_len;
					if (pad > 0) {
						ip_hdr_new->tot_len = htons((ip_hdr->ihl * 4) + size - pad);
					}
				}
				ip_hdr_new->check = 0;
				ip_hdr_new->check = in_cksum(ip_hdr_new, ip_hdr_new->ihl*4);
				temp_fpak_prev = temp_fpak_info;	
				if (data_offset >= (fpak_info->pak_hdr.caplen - hdrs_len)) {
					break;
				}
			}
		}
	}

}
