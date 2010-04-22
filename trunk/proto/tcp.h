/* tcp.h
 *
 * $Id: tcp.h 1 2010-04-11 21:04:36 vijay mohan $
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

#ifndef __TCP_H__
#define __TCP_H__

#include <stdint.h>
#include "ip.h"

struct tcphdr {
        uint16_t  source;
        uint16_t  dest;
        uint32_t  seq;
        uint32_t  ack_seq;
        uint16_t   res1:4,
                doff:4,
                fin:1,
                syn:1,
                rst:1,
                psh:1,
                ack:1,
                urg:1,
                ece:1,
                cwr:1;
        uint16_t  window;
        uint16_t check;
        uint16_t  urg_ptr;
};


void
display_tcp(uint8_t **pak);

uint16_t
ComputeTCPChecksum(struct tcphdr *tcp_header, struct iphdr *ip_header);

#endif
