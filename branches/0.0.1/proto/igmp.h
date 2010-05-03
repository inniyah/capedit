/* igmp.h
 *
 * $Id: igmp.h 1 2010-04-11 21:04:36 vijay mohan $
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

#ifndef __IGMP_H__
#define __IGMP_H__

#include<stdint.h>

struct igmpv3_grec {                                                          
        uint8_t    grec_type;                                                 
        uint8_t    grec_auxwords;                                             
        uint16_t   grec_nsrcs;                                                
        uint32_t   grec_mca;                                                  
        uint32_t   grec_src[0];                                               
}; 

union igmphdr {
	struct {    
	        uint8_t  type;
       		uint8_t  code;              /* For newer IGMP */
        	uint16_t csum;                                     
        	uint32_t group;                                                       
        	uint8_t  qrv:3,                                                       
                 	 suppress:1,                                                  
                 	 resv:4;                                                      
        	uint8_t  qqic;
        	uint16_t nsrcs;
        	uint32_t srcs[0];
	}igmpv3_query;
	struct {
                uint8_t  type;
                uint16_t csum;
        	uint16_t resv2;                                                       
        	uint16_t ngrec;                                                       
        	struct   igmpv3_grec grec[0];                                         
	}igmpv3_report;      
};

/*struct igmpv3_query {
        uint8_t  type;
        uint8_t  code;
        uint16_t csum;
        uint32_t group;
        uint8_t  qrv:3,
                 suppress:1,
                 resv:4;
        uint8_t  qqic;
        uint16_t nsrcs;
        uint32_t srcs[0];
};*/

/*
struct igmpv3_report {
        uint8_t  type;
        uint8_t  resv1;
        uint16_t csum;
        uint16_t resv2;
        uint16_t ngrec;
        struct   igmpv3_grec grec[0];
};
*/
void
display_igmp(uint8_t **pak);

void
update_igmp(char *value);



#endif
