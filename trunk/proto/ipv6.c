#include<stdio.h>
#include<stdint.h>
#include"../main.h"
#include<stdlib.h>
#include"../pakvalupdate.h"
#include "../packet.h"
#include "tcp.h"
#include "udp.h"

#include "ipv6.h"

uint8_t
display_ipv6(uint8_t **pak)
{
	struct ip6hdr *ip_hdr;
	uint32_t temp;

	ip_hdr = (struct ip6hdr *)*pak;
	ptree_append ("Internet Protocol(IPv6)",NULL,STRING,0, P_IPV6,0);	
    temp = ip_hdr->version;
	ptree_append ("Version:",&temp,UINT8,1, P_IPV6,0);
    temp = ip_hdr->tos;
    ptree_append("Tos:",&temp,UINT8_HEX_1,1, P_IPV6,0);
    temp = ip_hdr->flow_label;
    ptree_append("Flow Label:",&temp,UINT32,1, P_IPV6,0);
    ptree_append("Payload Length:",&ip_hdr->payload_length,UINT16,1, P_IPV6,0);
	ptree_append("Next Header:", &ip_hdr->next_header, UINT8,1, P_IPV6,0);
	ptree_append("Hop Limit:",&ip_hdr->hop_limit, UINT8, 1, P_IPV6,0);
    ptree_append("Source IP:",&(ip_hdr->saddr),IPV6_ADDR,1, P_IPV6,0);
    ptree_append("Destination IP:",&(ip_hdr->daddr),IPV6_ADDR,1, P_IPV6,0);


//	cur_pak_info.src_ip = ip_hdr->saddr;
//    cur_pak_info.dst_ip = ip_hdr->daddr;
    cur_pak_info.proto  = ip_hdr->next_header;
	*pak += 40;
	cur_pak_info.L4_off = cur_pak_info.L3_off + 40;
    return (ip_hdr->next_header);
}

void update_ipv6(char *value)
{
/*	struct ip6hdr *ip_hdr;
	uint16_t i16_1, i16_2;
        struct tcphdr *tcp_hdr;
        struct udphdr *udp_hdr;
	
	ip_hdr = (struct ip6hdr *)(fpak_curr_info->pak + cur_pak_info.L3_off);
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
		udp_hdr = (struct udphdr *)(fpak_curr_info->pak + cur_pak_info.L4_off);
		udp_hdr->check = ComputeUDPChecksum(udp_hdr, ip_hdr);
	} else if (ip_hdr->protocol == 0x06) {
		tcp_hdr = (struct tcphdr *)(fpak_curr_info->pak + cur_pak_info.L4_off);
		tcp_hdr->check = ComputeTCPChecksum(tcp_hdr, ip_hdr);
	}

*/}


