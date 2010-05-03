/* main.h
 *
 * $Id: main.h 1 2010-04-11 21:04:36 vijay mohan $
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

#ifndef __TREE_H__
#define __TREE_H__

#include<stdint.h>
#include<stdio.h>
#include "pcap.h"

extern struct pak_file_info *fpak_curr_info;
extern char ptype[50];
extern uint16_t p_ref_proto;
extern int record_l1;
extern int record_l2;
extern pcap_t *p;

enum {
	UINT8,
	UINT8D,
	UINT8_HEX_1,
	UINT8_HEX_2,
	UINT8_HEX_4,
	UINT16,
	UINT16D,
	UINT16HD,
	UINT16_HEX,
	UINT32,
	UINT32D,
	UINT32_HEX,
	UINT32_HEX_5,
	STRING,
	STRING_P,
	MAC,
	IPV4_ADDR,
	IPV6_ADDR
};

enum {
	P_ETH_II,
	P_VLAN_802_1Q,
	P_MPLS_UNICAST,
	P_ARP,
	P_IPV4,
	P_IPV6,
	P_GRE_IP,
	P_IGMP_QV3,
	P_IGMP_RV3,
	P_ICMP,
	P_UDP,
	P_TCP,
	P_DNS

};
struct pak_file_info {
	uint32_t pak_no;
	uint32_t offset;
	struct pcap_pkthdr pak_hdr;
	void *pak;
	uint8_t mem_alloc;
	uint16_t pak_len;
	struct pak_file_info *prev;
	struct pak_file_info *next;
};

void
init_main_window();

void
ptree_append(char *param, void *value, uint8_t type, uint8_t level, uint16_t p_ref_proto, uint16_t record_no, ...);

#endif
