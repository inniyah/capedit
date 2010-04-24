/* ip.c
 *
 * $Id: ip.c 1 2010-04-11 21:04:36 vijay mohan $
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

#include<stdio.h>
#include<stdint.h>
#include"../main.h"
#include<stdlib.h>
#include"../pakvalupdate.h"
#include "../packet.h"
#include "tcp.h"
#include "udp.h"

u_short
in_cksum(const u_short *addr, register u_int len)
{
        int nleft = len;
        const u_short *w = addr;
        u_short answer;
        int sum = 0;

        /*
 *  *          *  Our algorithm is simple, using a 32 bit accumulator (sum),
 *   *                   *  we add sequential 16 bit words to it, and at the end, fold
 *    *                            *  back all the carry bits from the top 16 bits into the lower
 *     *                                     *  16 bits.
 *      *                                              */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }
        if (nleft == 1)
                sum += htons(*(u_char *)w<<8);

        /*
 *  *          * add back carry outs from top 16 bits to low 16 bits
 *   *                   */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return (answer);
}

uint8_t
display_ip(uint8_t **pak, uint16_t l3_protocol)
{
	struct iphdr *ip_hdr;
	struct ip6hdr *ip6_hdr;
	struct grehdr *gre_hdr;
	struct sre *sre_hdr;
	uint32_t temp;
	uint16_t offset = 0;
	uint16_t mf_flag = 0;
	uint8_t grehdr_no = 0;
	uint8_t iphdr_no = 0;
	uint8_t i = 0;
	uint16_t hdrs_len = 0;
	uint8_t l4_protocol;

iphdr_parse:
	if (l3_protocol == 0x0800) {
		ip_hdr = (struct iphdr *)*pak;
		ptree_append ("Internet Protocol(IPv4)",NULL,STRING,0, P_IPV4, 0);	
		temp = ip_hdr->version;
		ptree_append ("Version:",&temp,UINT8,1, P_IPV4, 1, iphdr_no);
		temp = ip_hdr->ihl;
        	ptree_append("Header length:",&temp,UINT8,1, P_IPV4, 1, iphdr_no);
        	ptree_append("Tos:",&ip_hdr->tos,UINT8,1, P_IPV4, 1, iphdr_no);
        	ptree_append("Total length:",&ip_hdr->tot_len,UINT16,1, P_IPV4, 1, iphdr_no);
        	ptree_append("Identification:",&ip_hdr->id,UINT16_HEX,1, P_IPV4, 1, iphdr_no);
		temp = pak_get_bits_uint16(ip_hdr->frag_off, 15, 3);
		ptree_append("Flags:", &temp, UINT8_HEX_1 ,1, P_IPV4, 1, iphdr_no);
		temp = pak_get_bits_uint16(ip_hdr->frag_off, 15, 1);
		ptree_append("Reserved bit:", &temp, UINT8, 2, P_IPV4, 1, iphdr_no);
        	temp = pak_get_bits_uint16(ip_hdr->frag_off, 14, 1);
        	ptree_append("Don't fragment:", &temp, UINT8, 2, P_IPV4, 1, iphdr_no);
        	mf_flag = temp = pak_get_bits_uint16(ip_hdr->frag_off, 13, 1);
        	ptree_append("More fragments:", &temp, UINT8, 2, P_IPV4, 1, iphdr_no);
		offset = temp = pak_get_bits_uint16(ip_hdr->frag_off, 12, 13);
        	ptree_append("Fragment offset:",&temp,UINT16HD,1, P_IPV4, 1, iphdr_no);
        	ptree_append("Time to live:",&ip_hdr->ttl,UINT8,1, P_IPV4, 1, iphdr_no);
        	ptree_append("Protocol:",&ip_hdr->protocol,UINT8,1, P_IPV4, 1, iphdr_no);
        	ptree_append("Header checksum:",&ip_hdr->check,UINT16_HEX,1, P_IPV4, 1, iphdr_no);
        	ptree_append("Source IP:",&ip_hdr->saddr,IPV4_ADDR,1, P_IPV4, 1, iphdr_no);
        	ptree_append("Destination IP:",&ip_hdr->daddr,IPV4_ADDR,1, P_IPV4, 1, iphdr_no);
		*pak += (ip_hdr->ihl * 4);
		hdrs_len += (ip_hdr->ihl * 4);
		l4_protocol = ip_hdr->protocol;
		++iphdr_no;

		if (iphdr_no == 1) {
        		cur_pak_info.src_ip = ip_hdr->saddr;
        		cur_pak_info.dst_ip = ip_hdr->daddr;
        		cur_pak_info.proto  = ip_hdr->protocol;
		}
        	if ((mf_flag == 1) || (offset > 0)) {
                	cur_pak_info.L4_proto = 0;
                	return 0;
        	}
	} else if (l3_protocol == 0x86DD) {
        	ip6_hdr = (struct ip6hdr *)*pak;
        	ptree_append ("Internet Protocol(IPv6)",NULL,STRING,0, P_IPV6,0);
        	temp = pak_get_bits_uint32(ip6_hdr->vtf, 31, 4);
        	ptree_append ("Version:",&temp,UINT8,1, P_IPV6, 1, iphdr_no);
        	temp = pak_get_bits_uint32(ip6_hdr->vtf, 27, 8);
        	ptree_append("Tos:",&temp,UINT8_HEX_1,1, P_IPV6, 1, iphdr_no);
        	temp = pak_get_bits_uint32(ip6_hdr->vtf, 19, 20);
        	ptree_append("Flow Label:",&temp,UINT32_HEX_5, 1, P_IPV6, 1, iphdr_no);
        	ptree_append("Payload Length:",&ip6_hdr->payload_length,UINT16,1, P_IPV6, 1, iphdr_no);
        	ptree_append("Next Header:", &ip6_hdr->next_header, UINT8,1, P_IPV6, 1, iphdr_no);
        	ptree_append("Hop Limit:",&ip6_hdr->hop_limit, UINT8, 1, P_IPV6, 1, iphdr_no);
        	ptree_append("Source IP:",&(ip6_hdr->saddr),IPV6_ADDR,1, P_IPV6, 1, iphdr_no);
        	ptree_append("Destination IP:",&(ip6_hdr->daddr),IPV6_ADDR,1, P_IPV6, 1, iphdr_no);
		hdrs_len += sizeof(struct ip6hdr);
		*pak += sizeof(struct ip6hdr);
		l4_protocol = ip6_hdr->next_header;
		++iphdr_no;
	}

	if (l4_protocol == 0x04/*ipv4*/ || l4_protocol == 0x29/*ipv6*/) {
		goto iphdr_parse;
	}

	if (l4_protocol == 0x2f) {
		gre_hdr = (struct grehdr *)*pak;
		ptree_append ("Generic Routing Encapsulation(IP)",NULL,STRING,0, P_GRE_IP, 0);
		ptree_append("Flags and Version:",&gre_hdr->fandv, UINT16_HEX, 1, P_GRE_IP, 1, grehdr_no);
		temp = pak_get_bits_uint16(gre_hdr->fandv, 15, 1);
		ptree_append("Checksum Present:",&temp, UINT8, 2, P_GRE_IP, 1, grehdr_no);
		temp = pak_get_bits_uint16(gre_hdr->fandv, 14, 1);
		ptree_append("Routing Info Present:",&temp, UINT8, 2, P_GRE_IP, 1, grehdr_no);
                temp = pak_get_bits_uint16(gre_hdr->fandv, 13, 1);
                ptree_append("Key Present:",&temp, UINT8, 2, P_GRE_IP, 1, grehdr_no);
                temp = pak_get_bits_uint16(gre_hdr->fandv, 12, 1);
                ptree_append("Sequence Number Present:",&temp, UINT8, 2, P_GRE_IP, 1, grehdr_no);
                temp = pak_get_bits_uint16(gre_hdr->fandv, 11, 1);
                ptree_append("Strict Source Route:",&temp, UINT8, 2, P_GRE_IP, 1, grehdr_no);
                temp = pak_get_bits_uint16(gre_hdr->fandv, 10, 3);
                ptree_append("Recursion Control:",&temp, UINT8, 2, P_GRE_IP, 1, grehdr_no);
                temp = pak_get_bits_uint16(gre_hdr->fandv, 7, 5);
                ptree_append("Reserved:",&temp, UINT16_HEX, 2, P_GRE_IP, 1, grehdr_no);
                temp = pak_get_bits_uint16(gre_hdr->fandv, 2, 3);
                ptree_append("Version:",&temp, UINT8, 2, P_GRE_IP, 1, grehdr_no);
                temp = pak_get_bits_uint16(gre_hdr->fandv, 10, 3);
		ptree_append("Protocol Type:",&gre_hdr->protocol, UINT16_HEX, 1, P_GRE_IP, 1, grehdr_no);
		*pak += 4;
		hdrs_len += 4;
		if (pak_get_bits_uint16(gre_hdr->fandv, 15, 1) ||
		    pak_get_bits_uint16(gre_hdr->fandv, 14, 1)) {
			ptree_append("Checksum:",&gre_hdr->csum, UINT16_HEX, 1, P_GRE_IP, 1, grehdr_no);
			ptree_append("Offset:",&gre_hdr->offset, UINT16, 1, P_GRE_IP, 1, grehdr_no);	
			*pak += 4;
			hdrs_len += 4;
		}
		if (pak_get_bits_uint16(gre_hdr->fandv, 13, 1)) {
			ptree_append("Key:",&gre_hdr->key, UINT32, 1, P_GRE_IP, 1, grehdr_no);
			*pak += 4;
			hdrs_len += 4;
		}
		if (pak_get_bits_uint16(gre_hdr->fandv, 12, 1)) {
			ptree_append("Sequence:",&gre_hdr->seq_no, UINT32, 1, P_GRE_IP, 1, grehdr_no);
			*pak += 4;
			hdrs_len += 4;
		}
		if (pak_get_bits_uint16(gre_hdr->fandv, 14, 1)) {
			for (i=0,sre_hdr = (struct sre *)*pak;(sre_hdr->af != 0x0000) && (sre_hdr->offset != 0);i++) {
				ptree_append ("Generic Routing Encapsulation(IP)",NULL,STRING,1, P_GRE_IP, 0);
				ptree_append("Address Family:",&sre_hdr->af, UINT16_HEX, 2, P_GRE_IP, 2, grehdr_no, i);
				ptree_append("Offset:",&sre_hdr->offset, UINT8, 2, P_GRE_IP, 2, grehdr_no, i);
				ptree_append("Length:",&sre_hdr->offset, UINT8, 2, P_GRE_IP, 2, grehdr_no, i);
				*pak += (sizeof(struct sre) + sre_hdr->offset);
				hdrs_len += (sizeof(struct sre) + sre_hdr->offset);
				sre_hdr = (struct sre *)*pak;
			}
		}
		grehdr_no++;
		l3_protocol = ntohs(gre_hdr->protocol);
		goto iphdr_parse;
	}

	cur_pak_info.L4_off = cur_pak_info.L3_off + hdrs_len;
	cur_pak_info.L4_proto = l4_protocol;
	return cur_pak_info.L4_proto;
}

void update_ip(char *value)
{
	struct iphdr *ip_hdr;
	struct ip6hdr *ip6_hdr;
	struct grehdr *gre_hdr;
	uint8_t grehdr_len = 0;
	uint8_t sre_present = 0;
	struct sre *sre_hdr;
	struct sre *sre_temp;
	uint16_t i16_1, i16_2;
        struct tcphdr *tcp_hdr;
        struct udphdr *udp_hdr;
	uint8_t *pak;
	uint8_t i = 0;
	uint8_t l4_protocol  = 0;
	uint16_t l3_protocol = 0;
	uint16_t cur_protocol = 0;
	uint8_t ver = 0;
	
	pak = (uint8_t *)(fpak_curr_info->pak + cur_pak_info.L3_off);
	if (p_ref_proto == P_IPV4) {
		if (cur_pak_info.L3_proto == 0x0800) {
			ip_hdr = (struct iphdr *)pak;
			cur_protocol = ip_hdr->protocol;
			ver = 4;
		} else if (cur_pak_info.L3_proto == 0x86DD) {
			ip6_hdr = (struct ip6hdr *)pak;
			cur_protocol = ip6_hdr->next_header;
			ver = 6;
		}
		for (i = 0; (record_l1 > 0) && (i < record_l1); i++) {
			if (cur_protocol == 0x2f) {
				pak += (ver == 4)?(ip_hdr->ihl * 4):(sizeof(struct ip6hdr));
                  	        gre_hdr = (struct grehdr *)pak;
                        	if (pak_get_bits_uint16(gre_hdr->fandv, 15, 1) ||
                            		pak_get_bits_uint16(gre_hdr->fandv, 14, 1)) {
                                	pak += 8;
                        	} else {
                                	pak += 4;
                        	}
                        	if (pak_get_bits_uint16(gre_hdr->fandv, 13, 1)) {
                                	pak += 4;
                        	}
                        	if (pak_get_bits_uint16(gre_hdr->fandv, 12, 1)) {
                                	pak += 4;
                        	}
                        	if (pak_get_bits_uint16(gre_hdr->fandv, 14, 1)) {
                                	for (sre_hdr = (struct sre *)pak;(sre_hdr->af != 0x0000) && (sre_hdr->offset != 0);) {
                                        	pak += (sizeof(struct sre) + sre_hdr->offset);
                                        	sre_hdr = (struct sre *)pak;
                                	}
                        	}
				cur_protocol = ntohs(gre_hdr->protocol);
				if (cur_protocol == 0x0800) {
					ip_hdr = (struct iphdr *)pak;	
				} else if (cur_protocol == 0x86DD) {
					ip6_hdr = (struct ip6hdr *)pak;
				}
			} else if (cur_protocol == 0x04) {
				pak += (ip_hdr->ihl * 4);
				ip_hdr = (struct iphdr *)pak;
				cur_protocol = ip_hdr->protocol;
			} else if (cur_protocol == 0x29) {
				pak += (sizeof(struct ip6hdr));
				ip6_hdr = (struct ip6hdr *)pak;
				cur_protocol = ip6_hdr->next_header;
			}
		} 
		if (!strcmp(ptype,"Version:")) {
			ip_hdr->version = atoi(value);
		} else if (!strcmp(ptype,"Header length:")) {
			ip_hdr->ihl = atoi(value);
		} else if (!strcmp(ptype,"Tos:")) {
      			pak_val_update(&ip_hdr->tos, value, UINT8D); 
        	} else if (!strcmp(ptype,"Total length:")) {
       			pak_val_update(&ip_hdr->tot_len, value, UINT16D); 
        	} else if (!strcmp(ptype,"Identification:")) {
       			pak_val_update(&ip_hdr->id, value, UINT16_HEX); 
        	} else if (!strcmp(ptype,"Flags:")) {
			ip_hdr->frag_off = pak_set_bits_uint16_hex(ip_hdr->frag_off, 15, 3, value);
        	} else if (!strcmp(ptype,"Reserved bit:")) {
			ip_hdr->frag_off = pak_set_bits_uint16(ip_hdr->frag_off, 15, 1, value);
        	} else if (!strcmp(ptype,"Don't fragment:")) {
       			ip_hdr->frag_off = pak_set_bits_uint16(ip_hdr->frag_off, 14, 1, value); 
        	} else if (!strcmp(ptype,"More fragments:")) {
        		ip_hdr->frag_off = pak_set_bits_uint16(ip_hdr->frag_off, 13, 1, value);
        	} else if (!strcmp(ptype,"Fragment offset:")) {
			ip_hdr->frag_off = pak_set_bits_uint16D(ip_hdr->frag_off, 12, 13, value);
        	} else if (!strcmp(ptype,"Time to live:")) {
        		pak_val_update(&ip_hdr->ttl, value, UINT8);
        	} else if (!strcmp(ptype,"Protocol:")) {
        		pak_val_update(&ip_hdr->protocol, value, UINT8);
        	} else if (!strcmp(ptype,"Header checksum:")) {
        		pak_val_update(&ip_hdr->check, value, UINT16_HEX);
        	} else if (!strcmp(ptype,"Source IP:")) {
       			pak_val_update(&ip_hdr->saddr, value, IPV4_ADDR); 
        	} else if (!strcmp(ptype,"Destination IP:")) {
        		pak_val_update(&ip_hdr->daddr, value, IPV4_ADDR);
		}
      
		ip_hdr->check = 0;
		ip_hdr->check = in_cksum((u_short *)ip_hdr, ip_hdr->ihl*4);
		if (ip_hdr->protocol == 0x11) {
			udp_hdr = (struct udphdr *)(((uint8_t *)ip_hdr) + (ip_hdr->ihl * 4));
			udp_hdr->check = ComputeUDPChecksum(udp_hdr, ip_hdr);
		} else if (ip_hdr->protocol == 0x06) {
			tcp_hdr = (struct tcphdr *)(((uint8_t *)ip_hdr) + (ip_hdr->ihl * 4));
			tcp_hdr->check = ComputeTCPChecksum(tcp_hdr, ip_hdr);
		}
	}
	if (p_ref_proto == P_IPV6) {
                if (cur_pak_info.L3_proto == 0x0800) {
                        ip_hdr = (struct iphdr *)pak;
                        cur_protocol = ip_hdr->protocol;
                        ver = 4;
                } else if (cur_pak_info.L3_proto == 0x86DD) {
                        ip6_hdr = (struct ip6hdr *)pak;
                        cur_protocol = ip6_hdr->next_header;
                        ver = 6;
                }
                for (i = 0; (record_l1 > 0) && (i < record_l1); i++) {
                        if (cur_protocol == 0x2f) {
				pak += (ver == 4)?(ip_hdr->ihl * 4):(sizeof(struct ip6hdr));
                                gre_hdr = (struct grehdr *)pak;
                                if (pak_get_bits_uint16(gre_hdr->fandv, 15, 1) ||
                                        pak_get_bits_uint16(gre_hdr->fandv, 14, 1)) {
                                        pak += 8;
                                } else {
                                        pak += 4;
                                }
                                if (pak_get_bits_uint16(gre_hdr->fandv, 13, 1)) {
                                        pak += 4;
                                }
                                if (pak_get_bits_uint16(gre_hdr->fandv, 12, 1)) {
                                        pak += 4;
                                }
                                if (pak_get_bits_uint16(gre_hdr->fandv, 14, 1)) {
                                        for (sre_hdr = (struct sre *)pak;(sre_hdr->af != 0x0000) && (sre_hdr->offset != 0);) {
                                                pak += (sizeof(struct sre) + sre_hdr->offset);
                                                sre_hdr = (struct sre *)pak;
                                        }
                                }
                                cur_protocol = ntohs(gre_hdr->protocol);
                                if (cur_protocol == 0x0800) {
                                        ip_hdr = (struct iphdr *)pak;
                                } else if (cur_protocol == 0x86DD) {
                                        ip6_hdr = (struct ip6hdr *)pak;
                                }
                        } else if (cur_protocol == 0x04) {
                                pak += (ip_hdr->ihl * 4);
                                ip_hdr = (struct iphdr *)pak;
                                cur_protocol = ip_hdr->protocol;
                        } else if (cur_protocol == 0x29) {
                                pak += (sizeof(struct ip6hdr));
                                ip6_hdr = (struct ip6hdr *)pak;
                                cur_protocol = ip6_hdr->next_header;
                        }
                }
                if (!strcmp(ptype,"Version:")) {
                        ip6_hdr->vtf = pak_set_bits_uint32D(ip6_hdr->vtf, 31, 4, value);
                } else if (!strcmp(ptype,"Tos:")) {
                        ip6_hdr->vtf = pak_set_bits_uint32_hex(ip6_hdr->vtf, 27, 8, value);
                } else if (!strcmp(ptype,"Flow Label:")) {
                        ip6_hdr->vtf = pak_set_bits_uint32_hex(ip6_hdr->vtf, 19, 20, value);
                } else if (!strcmp(ptype,"Payload Length:")) {
                        pak_val_update(&ip6_hdr->payload_length, value, UINT16);
                } else if (!strcmp(ptype,"Next Header:")) {
                        pak_val_update(&ip6_hdr->next_header, value, UINT8);
                } else if (!strcmp(ptype,"Hop Limit:")) {
			pak_val_update(&ip6_hdr->hop_limit, value, UINT8);
                } else if (!strcmp(ptype,"Source IP:")) {
			pak_val_update(&ip6_hdr->saddr, value, IPV6_ADDR);
                } else if (!strcmp(ptype,"Destination IP:")) {
			pak_val_update(&ip6_hdr->daddr, value, IPV6_ADDR);
                }
	}
	if (p_ref_proto == P_GRE_IP) {
		ip_hdr = (struct iphdr *)pak;
		pak += (ip_hdr->ihl * 4);
		gre_hdr = (struct grehdr *)pak;
                for (i = 0; (record_l1 > 0) && (i < record_l1); i++) {
			if (pak_get_bits_uint16(gre_hdr->fandv, 15, 1) ||
			    pak_get_bits_uint16(gre_hdr->fandv, 14, 1)) {
				pak += 8;
			} else {
				pak += 4;
			}
			if (pak_get_bits_uint16(gre_hdr->fandv, 13, 1)) {
				pak += 4;
			}
			if (pak_get_bits_uint16(gre_hdr->fandv, 12, 1)) {
				pak += 4;
			}
			if (pak_get_bits_uint16(gre_hdr->fandv, 14, 1)) {
				for (sre_hdr = (struct sre *)pak;(sre_hdr->af != 0x0000) && (sre_hdr->offset != 0);) {
					pak += (sizeof(struct sre) + sre_hdr->offset);
					sre_hdr = (struct sre *)pak;
				}
				sre_present = 1;
			}
			ip_hdr = (struct iphdr *)pak;
			pak += (ip_hdr->ihl *4);
			gre_hdr = (struct grehdr *)pak;
		}
			if (pak_get_bits_uint16(gre_hdr->fandv, 15, 1) ||
                            pak_get_bits_uint16(gre_hdr->fandv, 14, 1)) {
                                pak += 8;
				grehdr_len += 8;
                        } else {
                                pak += 4;
				grehdr_len += 4;
                        }
                        if (pak_get_bits_uint16(gre_hdr->fandv, 13, 1)) {
                                pak += 4;
				grehdr_len += 4;
                        }
                        if (pak_get_bits_uint16(gre_hdr->fandv, 12, 1)) {
                                pak += 4;
				grehdr_len += 4;
                        }
                        if (pak_get_bits_uint16(gre_hdr->fandv, 14, 1)) {
                                for (i = 0, sre_temp = (struct sre *)pak; (sre_temp->af != 0x0000) && (sre_temp->offset != 0); i++) {
                                        pak += (sizeof(struct sre) + sre_temp->offset);
					grehdr_len += (sizeof(struct sre) + sre_temp->offset);
                                        sre_temp = (struct sre *)pak;
					if (i < record_l2) {
						sre_hdr = sre_temp;
					}
                                }
				grehdr_len += 4;
                        }

        if (!strcmp(ptype,"Flags and Version:")) {
                pak_val_update(&gre_hdr->fandv, value, UINT16_HEX);
        } else if (!strcmp(ptype,"Checksum Present:")) {
                gre_hdr->fandv = pak_set_bits_uint16(gre_hdr->fandv, 15, 1, value);
        } else if (!strcmp(ptype,"Routing Info Present:")) {
		gre_hdr->fandv = pak_set_bits_uint16(gre_hdr->fandv, 14, 1, value);
	} else if (!strcmp(ptype,"Key Present:")) {
                gre_hdr->fandv = pak_set_bits_uint16(gre_hdr->fandv, 13, 1, value);           
        } else if (!strcmp(ptype,"Sequence Number Present:")) {
                gre_hdr->fandv = pak_set_bits_uint16(gre_hdr->fandv, 12, 1, value);           
        } else if (!strcmp(ptype,"Strict Source Route:")) {
                gre_hdr->fandv = pak_set_bits_uint16(gre_hdr->fandv, 11, 1, value);           
        } else if (!strcmp(ptype,"Recursion Control:")) {
                gre_hdr->fandv = pak_set_bits_uint16(gre_hdr->fandv, 10, 3, value);           
        } else if (!strcmp(ptype,"Reserved:")) {
                gre_hdr->fandv = pak_set_bits_uint16(gre_hdr->fandv, 7, 5, value);           
        } else if (!strcmp(ptype,"Version:")) {
                gre_hdr->fandv = pak_set_bits_uint16(gre_hdr->fandv, 2, 3, value);           
        } else if (!strcmp(ptype,"Protocol Type:")) {
		pak_val_update(&gre_hdr->protocol, value, UINT16_HEX);
        } else if (!strcmp(ptype,"Checksum:")) {
		pak_val_update(&gre_hdr->csum, value, UINT16_HEX);
        } else if (!strcmp(ptype,"Offset:")) {
		pak_val_update(&gre_hdr->protocol, value, UINT16);
        } else if (!strcmp(ptype,"Key:")) {
		pak_val_update(&gre_hdr->key, value, UINT32);
        } else if (!strcmp(ptype,"Sequence:")) {
		pak_val_update(&gre_hdr->seq_no, value, UINT32);
        } else if (!strcmp(ptype, "Address Family:")) {
                gre_hdr->fandv = pak_set_bits_uint16(gre_hdr->fandv, 15, 1, value);           
        } else if (!strcmp(ptype, "Offset:")) {
                gre_hdr->fandv = pak_set_bits_uint16(gre_hdr->fandv, 15, 1, value);           
        } else if (!strcmp(ptype, "Length:")) {
                gre_hdr->fandv = pak_set_bits_uint16(gre_hdr->fandv, 15, 1, value);           
        } 
	if (pak_get_bits_uint16(gre_hdr->fandv, 15, 1)) {
		gre_hdr->csum = 0;
		gre_hdr->csum = in_cksum((void *)gre_hdr, grehdr_len);
	}
    }
}


