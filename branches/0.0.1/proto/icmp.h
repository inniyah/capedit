/* icmp.h
 *
 * $Id: icmp.h 1 2010-04-11 21:04:36 vijay mohan $
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

#ifndef __ICMP_H__
#define __ICMP_H__

#include <stdint.h>

struct icmphdr {
  uint8_t        type;
  uint8_t        code;
  uint16_t       checksum;
  uint16_t  	 id;
  uint16_t       sequence;
};



void
display_icmp(uint8_t **pak);

void
update_icmp(char *value);

#endif
