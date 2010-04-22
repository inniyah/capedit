/* packet.h
 *
 * $Id: packet.c 1 2010-04-11 21:04:36 vijay mohan $
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

#ifndef __PACKET_H__
#define __PACKET_H_

extern struct p_cur_pak_info cur_pak_info;

struct pl_decap_pak_info {
	char *src_ip;
	char *dst_ip;
	char *src_mac;
	char *dst_mac;
	uint8_t proto;
	uint16_t eth_proto;
	char protocol[20];
	char info[255];
	char row_color[20];
};

struct p_cur_pak_info 
{
        uint16_t L2_off;
        uint16_t L3_off;
        uint16_t L4_off;
        uint16_t L5_off;
        uint8_t  L4_proto;
	uint16_t L3_proto;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  proto;
	uint8_t  *src_mac;
	uint8_t  *dst_mac;
};

int
pl_decap_pak(uint8_t *buf,struct pl_decap_pak_info *pak_info);

struct pl_decap_pak_info *
malloc_pl_decap_pak_info(void);

void
free_pl_decap_pak_info(struct pl_decap_pak_info *);

void
display_pak(uint8_t *pak);

void
update_pak(char *value);

void
update_ether(char *value);


#endif
