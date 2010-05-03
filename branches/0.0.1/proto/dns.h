/* dns.h
 *
 * $Id: ip.h 1 2010-04-11 21:04:36 vijay mohan $
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

#ifndef __DNS_H__
#define __DNS_H__

#include<stdint.h>

struct res_record
{
uint8_t *name;
uint8_t *rdata;
uint16_t type;
uint16_t _class;
uint32_t ttl;
uint16_t data_len;
};


struct query
{
uint8_t *name;
uint16_t qtype;
uint16_t qclass;

};


struct dnshdr
{
uint16_t id;       // identification number
uint16_t flags;
/*
unsigned char rd :1;     // recursion desired
unsigned char tc :1;     // truncated message
unsigned char aa :1;     // authoritive answer
unsigned char opcode :4; // purpose of message
unsigned char qr :1;     // query/response flag
unsigned char rcode :4;  // response code
unsigned char cd :1;     // checking disabled
unsigned char ad :1;     // authenticated data
unsigned char z :1;      // its z! reserved
unsigned char ra :1;     // recursion available
*/
uint16_t q_count;  // number of question entries
uint16_t ans_count; // number of answer entries
uint16_t auth_count; // number of authority entries
uint16_t add_count; // number of resource entries
//struct res_record record_hdr[0];
};

void
display_dns(uint8_t **pak);
void
getres_record(uint8_t** tmp_buf, uint8_t** pak);
#endif
