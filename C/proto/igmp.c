/* igmp.c
 *
 * $Id: igmp.c 1 2010-04-11 21:04:36 vijay mohan $
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

#include "igmp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tcp.h"
#include <stdint.h>
#include "../main.h"
#include "../packet.h"

/*uint32_t group;
                uint8_t  qrv:3,
                        suppress:1,
                        resv:4;
                uint8_t  qqic;
                uint16_t nsrcs;
                uint32_t srcs[0];
        }igmpv3_query;
        union {
                uint16_t resv2;
                uint16_t ngrec;
                struct   igmpv3_grec grec[0];
        }igmpv3_report;
*/

void
display_igmp(uint8_t **pak)
{
	union igmphdr *igmp_hdr;
	uint8_t i8;
	uint16_t i16, i16_2;
	char buf[30];

	igmp_hdr = (union igmphdr *)*pak;
	if ((igmp_hdr->igmpv3_query.type == 0x11) || (igmp_hdr->igmpv3_query.type == 0x22)) {
		ptree_append ("Internet Group Management Protocol (IGMP Version : 3)", NULL, STRING, 0, P_IGMP_QV3, 0);
	}

	switch (igmp_hdr->igmpv3_query.type)
	{
	case 0x11:
	        ptree_append("Type:", &igmp_hdr->igmpv3_query.type, UINT8_HEX_2, 1, P_IGMP_QV3, 0);
        	ptree_append("Max Response Time:", &igmp_hdr->igmpv3_query.code, UINT8_HEX_2, 1, P_IGMP_QV3, 0);
        	ptree_append("Checksum:", &igmp_hdr->igmpv3_query.csum, UINT16_HEX, 1, P_IGMP_QV3, 0);
		ptree_append("Multicast Address:", &igmp_hdr->igmpv3_query.group, IPV4_ADDR, 1, P_IGMP_QV3, 0);
		ptree_append("QRV & S:", NULL, STRING, 1, P_IGMP_QV3, 0);
		i8 = igmp_hdr->igmpv3_query.qrv;
		ptree_append("qrv:", &i8, UINT8, 2, P_IGMP_QV3, 0);
		i8 = igmp_hdr->igmpv3_query.suppress;
		ptree_append("S:", &i8, UINT8, 2, P_IGMP_QV3, 0);
                i8 = igmp_hdr->igmpv3_query.resv;
                ptree_append("Reserved:", &i8, UINT8, 2, P_IGMP_QV3, 0);
		ptree_append("QQIC:", &igmp_hdr->igmpv3_query.qqic, UINT8, 1, P_IGMP_QV3, 0);
		ptree_append("Number Of Sources:", &igmp_hdr->igmpv3_query.nsrcs, UINT16, 1, P_IGMP_QV3, 0);
		for (i16 = 0; i16 < ntohs(igmp_hdr->igmpv3_query.nsrcs); ++i16) {
			ptree_append("Source Address:", &igmp_hdr->igmpv3_query.srcs[i16], IPV4_ADDR, 1, P_IGMP_QV3, 1, i16);
		}
		break;
	case 0x12:

		break;
	case 0x16:

		break;
        case 0x17:

		break;
        case 0x22:
		ptree_append("Type:", &igmp_hdr->igmpv3_report.type, UINT8_HEX_2, 1, P_IGMP_RV3, 0);
		ptree_append("Checksum:", &igmp_hdr->igmpv3_report.csum, UINT16_HEX, 1, P_IGMP_RV3, 0);
                ptree_append("Reserved Bits:", &igmp_hdr->igmpv3_report.resv2, UINT16, 1, P_IGMP_RV3, 0);
                ptree_append("Num Group Records:", &igmp_hdr->igmpv3_report.ngrec, UINT16, 1, P_IGMP_RV3, 0);
                for (i16 = 0; i16 < ntohs(igmp_hdr->igmpv3_report.ngrec); ++i16) {
                        ptree_append("Group Record:", NULL, STRING, 1, P_IGMP_RV3, 1, i16);
                        ptree_append("Record Type:", &igmp_hdr->igmpv3_report.grec[0].grec_type, UINT8, 2, P_IGMP_RV3, 1, i16);
                        ptree_append("Aux Data Len:", &igmp_hdr->igmpv3_report.grec[0].grec_auxwords, UINT8, 2, P_IGMP_RV3, 1, i16);
                        ptree_append("Num Src:", &igmp_hdr->igmpv3_report.grec[0].grec_nsrcs, UINT16, 2, P_IGMP_RV3, 1, i16);
                        ptree_append("Multicast Address:", &igmp_hdr->igmpv3_report.grec[0].grec_mca, IPV4_ADDR, 2, P_IGMP_RV3, 1, i16);
                        for (i16_2 = 0; i16 < ntohs(igmp_hdr->igmpv3_report.grec[0].grec_nsrcs); ++i16) {
                                ptree_append("Source Address:", &igmp_hdr->igmpv3_report.grec[0].grec_src[i16], IPV4_ADDR, 2, P_IGMP_RV3, 2, i16, i16_2);
                        }
                }
                break;

	}
}

void
update_igmp(char *value)
{
	struct iphdr *ip_hdr;
	union igmphdr *igmp_hdr;
	uint8_t i8;

	ip_hdr   = (struct iphdr *)(fpak_curr_info->pak + cur_pak_info.L3_off);
	igmp_hdr = (union igmphdr *)(fpak_curr_info->pak + cur_pak_info.L4_off);

	switch (p_ref_proto)
	{
	case P_IGMP_QV3:
		if (!strcmp(ptype,"Type:")) {
			pak_val_update(&igmp_hdr->igmpv3_query.type, value, UINT8_HEX_2);
		} else if (!strcmp(ptype,"Max Response Time:")) {
			pak_val_update(&igmp_hdr->igmpv3_query.code, value, UINT8_HEX_2);
		} else if (!strcmp(ptype,"Checksum:")) {
                        pak_val_update(&igmp_hdr->igmpv3_query.csum, value, UINT16_HEX);
                } else if (!strcmp(ptype,"Multicast Address:")) {
                        pak_val_update(&igmp_hdr->igmpv3_query.group, value, IPV4_ADDR);
                } else if (!strcmp(ptype,"qrv:")) {
			i8 = atoi(value);
                        igmp_hdr->igmpv3_query.qrv = i8;
                } else if (!strcmp(ptype,"S:")) {
			i8 = atoi(value);
                        igmp_hdr->igmpv3_query.suppress = i8;
                } else if (!strcmp(ptype,"Reserved:")) {
			i8 = atoi(value);
                        igmp_hdr->igmpv3_query.resv = i8;
                } else if (!strcmp(ptype,"QQIC:")) {
                        pak_val_update(&igmp_hdr->igmpv3_query.qqic, value, UINT8);
                } else if (!strcmp(ptype,"Number Of Sources:")) {
                        pak_val_update(&igmp_hdr->igmpv3_query.nsrcs, value, UINT16);
                } else if (!strcmp(ptype,"Source Address:")) {
                        pak_val_update(&igmp_hdr->igmpv3_query.srcs[record_l1], value, IPV4_ADDR);
                }
        	igmp_hdr->igmpv3_query.csum = 0;
        	igmp_hdr->igmpv3_query.csum = in_cksum(igmp_hdr, (ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4)));
		break;
	case P_IGMP_RV3:
                if (!strcmp(ptype,"Type:")) {
                        pak_val_update(&igmp_hdr->igmpv3_report.type, value, UINT8_HEX_2);
                } else if (!strcmp(ptype,"Checksum:")) {
                        pak_val_update(&igmp_hdr->igmpv3_report.csum, value, UINT16_HEX);
                } else if (!strcmp(ptype,"Reserved Bits:")) {
                        pak_val_update(&igmp_hdr->igmpv3_report.resv2, value, UINT16);
                } else if (!strcmp(ptype,"Num Group Records:")) {
                        pak_val_update(&igmp_hdr->igmpv3_report.ngrec, value, UINT16);
                } else if (!strcmp(ptype,"Record Type:")) {
                        pak_val_update(&igmp_hdr->igmpv3_report.grec[record_l1].grec_type, value, UINT8);
                } else if (!strcmp(ptype,"Aux Data Len:")) {
                        pak_val_update(&igmp_hdr->igmpv3_report.grec[record_l1].grec_auxwords, value, UINT8);
                } else if (!strcmp(ptype,"Num Src:")) {
                        pak_val_update(&igmp_hdr->igmpv3_report.grec[record_l1].grec_nsrcs, value, UINT16);
                } else if (!strcmp(ptype,"Multicast Address:")) {
                        pak_val_update(&igmp_hdr->igmpv3_report.grec[record_l1].grec_mca, value, IPV4_ADDR);
                } else if (!strcmp(ptype,"Source Address:")) {
                        pak_val_update(&igmp_hdr->igmpv3_report.grec[record_l1].grec_src[record_l2], value, IPV4_ADDR);
                } 
                igmp_hdr->igmpv3_report.csum = 0;
                igmp_hdr->igmpv3_report.csum = in_cksum(igmp_hdr, (ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4)));
		break;
	} 
		
}
