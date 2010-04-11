/* arp.h
 *
 * $Id: arp.h 1 2010-04-11 21:04:36 vijay mohan $
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

#ifndef __ARP_H__
#define __ARP_H__

#include <stdint.h>

struct arphdr
{
        uint16_t          ar_hrd;         /* format of hardware address   */
        uint16_t          ar_pro;         /* format of protocol address   */
        uint8_t   	  ar_hln;         /* length of hardware address   */
        uint8_t   	  ar_pln;         /* length of protocol address   */
        uint16_t          ar_op;          /* ARP opcode (command)         */


         /*
          *      Ethernet looks like this : This bit is variable sized however...
          */
        uint8_t           ar_sha[6];       /* sender hardware address      */
        uint8_t           ar_sip[4];       /* sender IP address            */
        uint8_t           ar_tha[6];       /* target hardware address      */
        uint8_t           ar_tip[4];       /* target IP address            */

};

void
display_arp(uint8_t **pak);

void
update_arp(char *value);

#endif
