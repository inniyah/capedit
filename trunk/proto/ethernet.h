/* ethernet.h
 *
 * $Id: ethernet.h 1 2010-04-11 21:04:36 vijay mohan $
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

#ifndef __ETHERNET_H__
#define __ETHERNET_H__

#include<stdint.h>
#include<stdint.h>

#define __packed

struct ether_addr
{
  uint8_t ether_addr_octet[6];
} __attribute__ ((__packed__));


struct ethhdr {
        uint8_t   h_dest[6];       /* destination eth addr */
        uint8_t   h_source[6];     /* source ether addr    */
        uint16_t  h_proto;         /* packet type ID field */
} __attribute__((packed));


struct vlan_802_1q {
	uint16_t priority:3,
		 cfi:1,
		 id:12;
	uint16_t protocol;
};

struct mplshdr {
	uint32_t label:20,
		 exp:3,
		 stack:1,
		 ttl:8;
	uint32_t mpls_next[0];
};



uint16_t
display_ether(uint8_t **pak);

void
update_ether(char *value);

#endif
