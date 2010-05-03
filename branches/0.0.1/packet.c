/* packet.c
 *
 * $Id: packet.c 1 2010-04-11 21:04:36 vijay mohan $
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "to_str.h"
#include <arpa/inet.h>
#include "packet.h"
#include <stdlib.h> 
#include "main.h"
#include "proto/ethernet.h"
#include "proto/udp.h"
#include "proto/tcp.h"
#include "proto/arp.h"
#include "proto/icmp.h"
#include "proto/igmp.h"
#include <gtk/gtk.h>

struct p_cur_pak_info cur_pak_info;

pl_decap_pak(uint8_t *buf,struct pl_decap_pak_info *pak_info)
{
	struct ethhdr *eth_hdr;
	struct vlan_802_1q *vlan_hdr;
	struct mplshdr *mpls_hdr;
	struct iphdr  *ip_hdr;
	struct ip6hdr *ip6_hdr;
	struct grehdr *gre_hdr; 
	struct sre    *sre_hdr;
	struct udphdr *udp_hdr;
	struct tcphdr *tcp_hdr;
	struct icmphdr *icmp_hdr;
	struct arphdr  *arp_hdr;
	uint8_t *tptr = buf;

	eth_hdr = (struct ethhdr *)tptr;
	pak_info->src_mac = ether_to_str((uint8_t *)eth_hdr->h_source);
	pak_info->dst_mac = ether_to_str((uint8_t *)eth_hdr->h_dest);
	pak_info->eth_proto = ntohs(eth_hdr->h_proto);	
  	strcpy(pak_info->row_color, "#E3E3E3");
	strcpy(pak_info->info, " ");
	strcpy(pak_info->protocol, "UNKNOWN");


	tptr += sizeof(struct ethhdr);
	for (;pak_info->eth_proto == 0x8100;) {
		vlan_hdr = (struct vlan_802_1q *)tptr;
		pak_info->eth_proto = ntohs(vlan_hdr->protocol);
		tptr += sizeof(struct vlan_802_1q);
	} 
	for (;pak_info->eth_proto == 0x8847;) {
		mpls_hdr = (struct mplshdr *)tptr;
		tptr += sizeof(struct mplshdr);	
		if (pak_get_bits_uint32(*(uint32_t *)mpls_hdr, 8, 1) == 1) {
			pak_info->eth_proto = 0x0800;
			break;
		}
	}
	if ((pak_info->eth_proto == 0x0800) || (pak_info->eth_proto == 0x86DD)) { /*ETH_P_IP*/
iphdr_parse:
		if (pak_info->eth_proto == 0x0800) {
			ip_hdr = (struct iphdr *)tptr;
			pak_info->src_ip = ip_to_str((uint8_t *)&(ip_hdr->saddr));
			pak_info->dst_ip = ip_to_str((uint8_t *)&(ip_hdr->daddr));
			pak_info->proto  = ip_hdr->protocol;
			strcpy(pak_info->protocol, "IP");
			tptr += (ip_hdr->ihl * 4);
			if (pak_get_bits_uint16(ip_hdr->frag_off, 13, 1) || 
		    		(pak_get_bits_uint16(ip_hdr->frag_off, 12, 13) > 0)) {
				strcpy(pak_info->info, "Fragmented IP Packet");
				return 1;
			}
		} else if (pak_info->eth_proto == 0x86DD) {
			ip6_hdr = (struct ip6hdr *)tptr;
			char buf[128];
			pak_info->dst_ip=(char*) malloc(128);
			pak_info->src_ip=(char*) malloc(128);
			inet_ntop(AF_INET6, &(ip6_hdr->saddr), buf, 128);
			sprintf(pak_info->src_ip,"%s",buf);
			inet_ntop(AF_INET6, &(ip6_hdr->daddr), buf, 128);
			sprintf(pak_info->dst_ip,"%s",buf);
			strcpy(pak_info->protocol, "IPV6");
			pak_info->proto  = ip6_hdr->next_header;
			tptr += sizeof(struct ip6hdr);
		}
		if (pak_info->proto == 0x04 || pak_info->proto == 0x29) {
			goto iphdr_parse;
		}
		if (pak_info->proto == 0x2f) {
			gre_hdr = (struct grehdr *)tptr;	
			if (pak_get_bits_uint16(gre_hdr->fandv, 15, 1) ||
			    pak_get_bits_uint16(gre_hdr->fandv, 14, 1)) {
				tptr += 8;	
			} else {
				tptr += 4;
			}
			if (pak_get_bits_uint16(gre_hdr->fandv, 13, 1)) {
				tptr += 4;
			}
			if (pak_get_bits_uint16(gre_hdr->fandv, 12, 1)) {
                                tptr += 4;
                        }
			if (pak_get_bits_uint16(gre_hdr->fandv, 14, 1)) {
				for (sre_hdr = (struct sre *)tptr;(sre_hdr->af != 0x0000) && (sre_hdr->offset != 0);) {				
                                	tptr += (sizeof(struct sre) + sre_hdr->offset);
					sre_hdr = (struct sre *)tptr;
				}
                        } 
			pak_info->eth_proto = ntohs(gre_hdr->protocol);
			goto iphdr_parse;
		}
		if (pak_info->proto == 0x11) {
			udp_hdr = (struct udphdr *)tptr;
			strcpy(pak_info->protocol, "UDP");
			strcpy(pak_info->row_color, "#70DFFF");
			sprintf(pak_info->info, "%u > %u", ntohs(udp_hdr->source), ntohs(udp_hdr->dest));
		} else if (pak_info->proto == 0x06) {
			tcp_hdr = (struct tcphdr *)tptr;
			strcpy(pak_info->protocol, "TCP");
			strcpy(pak_info->row_color, "#8CFF7F");
			if ((tcp_hdr->syn == 1) && (tcp_hdr->ack != 1)) {
				sprintf(pak_info->info, "%u > %u [SYN] Seq = %u", ntohs(tcp_hdr->source), 
					ntohs(tcp_hdr->dest), ntohl(tcp_hdr->seq));
			} else if ((tcp_hdr->syn == 1) && (tcp_hdr->ack == 1)) {
                                sprintf(pak_info->info, "%u > %u [SYN, ACK] Seq = %u Ack=%u", ntohs(tcp_hdr->source),
                                        ntohs(tcp_hdr->dest), ntohl(tcp_hdr->seq), ntohl(tcp_hdr->ack_seq));
			} else if ((tcp_hdr->syn != 1) && (tcp_hdr->ack == 1)) {
                                sprintf(pak_info->info, "%u > %u [ACK] Seq = %u Ack=%u", ntohs(tcp_hdr->source),
                                        ntohs(tcp_hdr->dest), ntohl(tcp_hdr->seq), ntohl(tcp_hdr->ack_seq));
			} else if ((tcp_hdr->fin == 1) && (tcp_hdr->ack == 1)) {
                                sprintf(pak_info->info, "%u > %u [FIN, ACK] Seq = %u Ack=%u", ntohs(tcp_hdr->source),
                                        ntohs(tcp_hdr->dest), ntohl(tcp_hdr->seq), ntohl(tcp_hdr->ack_seq));
                        } else if ((tcp_hdr->fin == 1) && (tcp_hdr->ack != 1)) {
                                sprintf(pak_info->info, "%u > %u [FIN] Seq = %u Ack=%u", ntohs(tcp_hdr->source),
                                        ntohs(tcp_hdr->dest), ntohl(tcp_hdr->seq), ntohl(tcp_hdr->ack_seq));
                        } else {
                                sprintf(pak_info->info, "%u > %u  Seq = %u Ack=%u", ntohs(tcp_hdr->source),
                                        ntohs(tcp_hdr->dest), ntohl(tcp_hdr->seq), ntohl(tcp_hdr->ack_seq));
			}
		} else if (pak_info->proto == 0x01) {
			tptr += (ip_hdr->ihl * 4);
			icmp_hdr = (struct icmphdr *)tptr;
			strcpy(pak_info->protocol, "ICMP");
			strcpy(pak_info->row_color, "#C1C2FF");
			if (icmp_hdr->type == 0) {
				sprintf(pak_info->info, "Echo Reply");
			} else if (icmp_hdr->type == 8) {
				sprintf(pak_info->info, "Echo Request");
			} else {
				sprintf(pak_info->info, "icmp type=%d code=%d", icmp_hdr->type, icmp_hdr->code);
			}
                } else if (pak_info->proto == 0x02) {
                        sprintf(pak_info->protocol, "IGMP");
                        sprintf(pak_info->info, "igmp packet");
			strcpy(pak_info->row_color, "#FFF3D5");
		} else {
			sprintf(pak_info->protocol, "0x%02x", pak_info->proto);
			sprintf(pak_info->info, "NOT SUPPORTED");
			strcpy(pak_info->row_color, "red");
		}
	} else if (pak_info->eth_proto == 0x0806) {
		arp_hdr = (struct arphdr *)tptr;
		strcpy(pak_info->protocol, "ARP");
		strcpy(pak_info->row_color, "#D6E7FF");
		if (ntohs(arp_hdr->ar_op) == 0x1) {
			sprintf(pak_info->info, "Arp Request");
		} else if (ntohs(arp_hdr->ar_op) == 0x2) {
			sprintf(pak_info->info, "Arp Reply");
		}
		return (0);
		
	} else {
		return (0);
	}
	
	return (1);	
}

void
free_pl_decap_pak_info(struct pl_decap_pak_info *pak_info)
{
        if (pak_info->src_ip != NULL) {
		free((void *)pak_info->src_ip);
		pak_info->src_ip = NULL;
	}
        if (pak_info->dst_ip != NULL) {
		free((void *)pak_info->dst_ip);
		pak_info->dst_ip = NULL;
	}
        if (pak_info->src_mac != NULL) {
		free((void *)pak_info->src_mac);
		pak_info->src_mac = NULL;
	}
        if (pak_info->dst_mac != NULL) {
		free((void *)pak_info->dst_mac);
		pak_info->dst_mac = NULL;
	}
}

struct pl_decap_pak_info *
malloc_pl_decap_pak_info(void)
{
	struct pl_decap_pak_info *temp;
	
	temp = (struct pl_decap_pak_info *)malloc(sizeof(struct pl_decap_pak_info));
	temp->src_ip = NULL;
        temp->dst_ip = NULL;
        temp->src_mac = NULL;
        temp->dst_mac = NULL;
        temp->proto   = 0;
        temp->eth_proto = 0;

	return temp;
}

uint16_t
display_L2(uint8_t **pak)
{
	return(display_ether(pak));
}

uint8_t
display_L3(uint8_t **pak, uint16_t L3_proto)
{
	if (L3_proto == 0x0800 || L3_proto == 0x86DD) {            	/* Internet Protocol packet     */
		return (display_ip(pak, L3_proto));
    	} else if (L3_proto == 0x0806) {        /* Address Resolution packet    */
		display_arp(pak);
		return 0;
	} else {
        	return 0;
    }

}

uint16_t
display_L4(uint8_t **pak, uint8_t L4_proto)
{
	if (L4_proto == 0x11) { 	/*UDP*/
		display_udp(pak);
	} else if (L4_proto == 0x06) {  /*TCP*/
		display_tcp(pak);
	} else if (L4_proto == 0x01) {  /*ICMP*/
		display_icmp(pak);
	} else if (L4_proto == 0x02) {  /*IGMP*/
                display_igmp(pak);
        } else {
		return 0;	
	}
}

void
display_L5(uint8_t **pak)
{
	if (cur_pak_info.src_port == 53 || cur_pak_info.dst_port == 53) {
		display_dns(pak);
	}
}


void
display_pak(uint8_t *pak)
{
	uint16_t L3_proto;
	uint8_t  L4_proto;
	uint16_t L5_proto;
	uint8_t *hdr_cur = pak;

	L3_proto = display_L2(&hdr_cur);
	L4_proto = display_L3(&hdr_cur, L3_proto);
	L5_proto = display_L4(&hdr_cur, L4_proto);
	display_L5(&hdr_cur);

}

void
update_L2(char *value)
{
        if ((p_ref_proto == P_ETH_II) || (p_ref_proto == P_VLAN_802_1Q) || (p_ref_proto == P_MPLS_UNICAST)) {
                update_ether(value);
        }

}

void
update_L3(char *value)
{
	if ((p_ref_proto == P_IPV4) || (p_ref_proto == P_GRE_IP) || (p_ref_proto == P_IPV6)) {
		update_ip(value);

	} else if (p_ref_proto == P_ARP) {
		update_arp(value);	
	}
}

void
update_L4(char *value)
{
	if (p_ref_proto == P_UDP) {
		update_udp(value);
	} else if (p_ref_proto == P_TCP) {
		update_tcp(value);
	} else if (p_ref_proto == P_ICMP) {
		update_icmp(value);
	} else if ((p_ref_proto == P_IGMP_QV3) || (p_ref_proto == P_IGMP_RV3)) {
		update_igmp(value);
	} 
}

void
update_L5(char *value)
{

}

void
update_pak(char *value)
{
	update_L2(value);
	update_L3(value);
	update_L4(value);
}

uint8_t
update_stream(const gchar *src_mac, const gchar *dst_mac, const gchar *src_ip, const gchar *dst_ip, const gchar *src_port, const gchar *dst_port)
{
        struct ethhdr *eth_hdr;
        struct vlan_802_1q *vlan_hdr;
        struct mplshdr *mpls_hdr;
	struct iphdr *ip_hdr;
	struct tcphdr *tcp_hdr;
	struct udphdr *udp_hdr;
	uint8_t pak_reversed = 0;
        uint8_t *pak;
        uint16_t protocol;

        pak = fpak_curr_info->pak;
        eth_hdr = (struct ethhdr *)pak;
        protocol = eth_hdr->h_proto;
        pak += sizeof(struct ethhdr);
        for (;protocol == 0x0081;) {
                vlan_hdr = (struct vlan_802_1q *)pak;
                protocol = vlan_hdr->protocol;
                pak += sizeof(struct vlan_802_1q);
        }
        for (;protocol == 0x4788;) {
                mpls_hdr = (struct mplshdr *)pak;
                pak += sizeof(struct mplshdr);
                if (pak_get_bits_uint32(*(uint32_t *)mpls_hdr, 8, 1) == 1) {
                        protocol = 0x0008;
                        break;
                }
        }
        if (protocol == 0x0008) {
                ip_hdr = (struct iphdr *)pak;
		if ((ip_hdr->saddr == cur_pak_info.src_ip) || (ip_hdr->saddr == cur_pak_info.dst_ip) && 
				((ip_hdr->daddr == cur_pak_info.src_ip) || (ip_hdr->daddr == cur_pak_info.dst_ip))) {
			if (ip_hdr->saddr != cur_pak_info.src_ip) {
				pak_reversed = 1;
			}
			if (ip_hdr->protocol == 0x11) {
				udp_hdr = (struct udphdr *)(pak + ip_hdr->ihl * 4);
				if (((udp_hdr->source == cur_pak_info.src_port) || (udp_hdr->source == cur_pak_info.dst_port)) &&
					(udp_hdr->dest == cur_pak_info.src_port) || (udp_hdr->dest == cur_pak_info.dst_port)) {
					if (pak_reversed == 0) {
						pak_val_update(eth_hdr->h_source, src_mac, MAC);
						pak_val_update(eth_hdr->h_dest, dst_mac, MAC);
						pak_val_update(&ip_hdr->saddr, src_ip, IPV4_ADDR);
						pak_val_update(&ip_hdr->daddr, dst_ip, IPV4_ADDR);
						pak_val_update(&udp_hdr->source, src_port, UINT16D);
						pak_val_update(&udp_hdr->dest, dst_port, UINT16D);
						ip_hdr->check = 0;
						ip_hdr->check = in_cksum(ip_hdr, ip_hdr->ihl*4);
						udp_hdr->check = ComputeUDPChecksum(udp_hdr, ip_hdr);
						return (1);
					} else if (pak_reversed == 1) {
                                                pak_val_update(eth_hdr->h_source, dst_mac, MAC);
                                                pak_val_update(eth_hdr->h_dest, src_mac, MAC);
                                                pak_val_update(&ip_hdr->saddr, dst_ip, IPV4_ADDR);
                                                pak_val_update(&ip_hdr->daddr, src_ip, IPV4_ADDR);
                     				pak_val_update(&udp_hdr->source, src_port, UINT16D);
                                                pak_val_update(&udp_hdr->dest, dst_port, UINT16D);
						ip_hdr->check = 0;
						ip_hdr->check = in_cksum(ip_hdr, ip_hdr->ihl*4);
						udp_hdr->check = ComputeUDPChecksum(udp_hdr, ip_hdr);
						return (1);
					}
				}
			} else if (ip_hdr->protocol == 0x06) {
				tcp_hdr = (struct tcphdr *)(pak + ip_hdr->ihl * 4);
				if (((tcp_hdr->source == cur_pak_info.src_port) || (tcp_hdr->source == cur_pak_info.dst_port)) &&
                                        (tcp_hdr->dest == cur_pak_info.src_port) || (tcp_hdr->dest == cur_pak_info.dst_port)) {
                                        if (pak_reversed == 0) {
                                                pak_val_update(eth_hdr->h_source, src_mac, MAC);
                                                pak_val_update(eth_hdr->h_dest, dst_mac, MAC);
                                                pak_val_update(&ip_hdr->saddr, src_ip, IPV4_ADDR);
                                                pak_val_update(&ip_hdr->daddr, dst_ip, IPV4_ADDR);
						pak_val_update(&tcp_hdr->source, src_port, UINT16D);
						pak_val_update(&tcp_hdr->dest, dst_port, UINT16D);
						ip_hdr->check = 0;
						ip_hdr->check = in_cksum(ip_hdr, ip_hdr->ihl*4);
						tcp_hdr->check = ComputeTCPChecksum(tcp_hdr, ip_hdr);
						return (1);
                                        } else if (pak_reversed == 1) {
                                                pak_val_update(eth_hdr->h_source, dst_mac, MAC);
                                                pak_val_update(eth_hdr->h_dest, src_mac, MAC);
                                                pak_val_update(&ip_hdr->saddr, dst_ip, IPV4_ADDR);
                                                pak_val_update(&ip_hdr->daddr, src_ip, IPV4_ADDR);
                                            	pak_val_update(&tcp_hdr->source, src_port, UINT16D);
                                                pak_val_update(&tcp_hdr->dest, dst_port, UINT16D);
						ip_hdr->check = 0;
						ip_hdr->check = in_cksum(ip_hdr, ip_hdr->ihl*4);
						tcp_hdr->check = ComputeTCPChecksum(tcp_hdr, ip_hdr);
						return (1);
                                        }

				}
			}
		}
	}
	return (0);
}

uint8_t
update_mac_ip(const gchar *src_mac, const gchar *dst_mac, const gchar *src_ip, const gchar *dst_ip)
{
        struct ethhdr *eth_hdr;
        struct vlan_802_1q *vlan_hdr;
        struct mplshdr *mpls_hdr;
        struct iphdr *ip_hdr;
        struct tcphdr *tcp_hdr;
        struct udphdr *udp_hdr;
        uint8_t pak_reversed = 0;
	uint8_t *pak;
	uint16_t protocol;

	pak = fpak_curr_info->pak;
        eth_hdr = (struct ethhdr *)pak;
	protocol = eth_hdr->h_proto;
	pak += sizeof(struct ethhdr);
        for (;protocol == 0x0081;) {
                vlan_hdr = (struct vlan_802_1q *)pak;
                protocol = vlan_hdr->protocol;
                pak += sizeof(struct vlan_802_1q);
        }
        for (;protocol == 0x4788;) {
                mpls_hdr = (struct mplshdr *)pak;
                pak += sizeof(struct mplshdr);
                if (pak_get_bits_uint32(*(uint32_t *)mpls_hdr, 8, 1) == 1) {
                        protocol = 0x0008;
                        break;
                }
        }
        if (protocol == 0x0008) {
                ip_hdr = (struct iphdr *)pak;
                if ((ip_hdr->saddr == cur_pak_info.src_ip) || (ip_hdr->saddr == cur_pak_info.dst_ip) &&
                                ((ip_hdr->daddr == cur_pak_info.src_ip) || (ip_hdr->daddr == cur_pak_info.dst_ip))) {
                        if (ip_hdr->saddr != cur_pak_info.src_ip) {
                                pak_reversed = 1;
                        }
                        if (ip_hdr->protocol == 0x11) {
                                udp_hdr = (struct udphdr *)(fpak_curr_info->pak + sizeof(struct ethhdr) + ip_hdr->ihl * 4);
                                        if (pak_reversed == 0) {
                                                pak_val_update(eth_hdr->h_source, src_mac, MAC);
                                                pak_val_update(eth_hdr->h_dest, dst_mac, MAC);
                                                pak_val_update(&ip_hdr->saddr, src_ip, IPV4_ADDR);
                                                pak_val_update(&ip_hdr->daddr, dst_ip, IPV4_ADDR);
                                                ip_hdr->check = 0;
                                                ip_hdr->check = in_cksum(ip_hdr, ip_hdr->ihl*4);
                                                udp_hdr->check = ComputeUDPChecksum(udp_hdr, ip_hdr);
						return (1);
                                        } else if (pak_reversed == 1) {
                                                pak_val_update(eth_hdr->h_source, dst_mac, MAC);
                                                pak_val_update(eth_hdr->h_dest, src_mac, MAC);
                                                pak_val_update(&ip_hdr->saddr, dst_ip, IPV4_ADDR);
                                                pak_val_update(&ip_hdr->daddr, src_ip, IPV4_ADDR);
                                                ip_hdr->check = 0;
                                                ip_hdr->check = in_cksum(ip_hdr, ip_hdr->ihl*4);
                                                udp_hdr->check = ComputeUDPChecksum(udp_hdr, ip_hdr);
						return (1);
                                        }
                        } else if (ip_hdr->protocol == 0x06) {
                                tcp_hdr = (struct tcphdr *)(fpak_curr_info->pak + sizeof(struct ethhdr) + ip_hdr->ihl * 4);
                                        if (pak_reversed == 0) {
                                                pak_val_update(eth_hdr->h_source, src_mac, MAC);
                                                pak_val_update(eth_hdr->h_dest, dst_mac, MAC);
                                                pak_val_update(&ip_hdr->saddr, src_ip, IPV4_ADDR);
                                                pak_val_update(eth_hdr->h_dest, dst_mac, MAC);
                                                pak_val_update(&ip_hdr->saddr, src_ip, IPV4_ADDR);
                                                pak_val_update(&ip_hdr->daddr, dst_ip, IPV4_ADDR);
                                                ip_hdr->check = 0;
                                                ip_hdr->check = in_cksum(ip_hdr, ip_hdr->ihl*4);
                                                tcp_hdr->check = ComputeTCPChecksum(tcp_hdr, ip_hdr);
						return (1);
                                        } else if (pak_reversed == 1) {
                                                pak_val_update(eth_hdr->h_source, dst_mac, MAC);
                                                pak_val_update(eth_hdr->h_dest, src_mac, MAC);
                                                pak_val_update(&ip_hdr->saddr, dst_ip, IPV4_ADDR);
                                                pak_val_update(&ip_hdr->daddr, src_ip, IPV4_ADDR);
                                                ip_hdr->check = 0;
                                                ip_hdr->check = in_cksum(ip_hdr, ip_hdr->ihl*4);
                                                tcp_hdr->check = ComputeTCPChecksum(tcp_hdr, ip_hdr);
						return (1);
                                        }
                        } else if ((ip_hdr->protocol == 0x02) || (ip_hdr->protocol == 0x01)) {
                                        if (pak_reversed == 0) {
                                                pak_val_update(eth_hdr->h_source, src_mac, MAC);
                                                pak_val_update(eth_hdr->h_dest, dst_mac, MAC);
                                                pak_val_update(&ip_hdr->saddr, src_ip, IPV4_ADDR);
                                                pak_val_update(eth_hdr->h_dest, dst_mac, MAC);
                                                pak_val_update(&ip_hdr->saddr, src_ip, IPV4_ADDR);
                                                pak_val_update(&ip_hdr->daddr, dst_ip, IPV4_ADDR);
                                                ip_hdr->check = 0;
                                                ip_hdr->check = in_cksum(ip_hdr, ip_hdr->ihl*4);
                                                return (1);
                                        } else if (pak_reversed == 1) {
                                                pak_val_update(eth_hdr->h_source, dst_mac, MAC);
                                                pak_val_update(eth_hdr->h_dest, src_mac, MAC);
                                                pak_val_update(&ip_hdr->saddr, dst_ip, IPV4_ADDR);
                                                pak_val_update(&ip_hdr->daddr, src_ip, IPV4_ADDR);
                                                ip_hdr->check = 0;
                                                ip_hdr->check = in_cksum(ip_hdr, ip_hdr->ihl*4);
                                                return (1);
                                        }

			}
                }
        }
	return (0);
}

void
to_ipv6 (struct pak_file_info *fpak_info)
{
        void *pak = NULL;
	void *pak_start = NULL;
        uint8_t *new_pak = NULL;
        uint8_t *data = NULL;
        uint16_t data_len = 0;
        uint16_t hdrs_len = 0;
        uint16_t pad = 0;
        uint16_t ip_offset = 0;
        uint16_t data_offset = 0;
        struct ethhdr *eth_hdr;
        struct vlan_802_1q *vlan_hdr;
        struct iphdr  *ip_hdr;
	struct ip6hdr ip6_hdr;
	struct tcphdr *tcp_hdr;
	struct udphdr *udp_hdr;
        uint16_t protocol;
        struct pak_file_info *temp_fpak_info;
        struct pak_file_info *last, *temp_fpak_prev;


        if (fpak_info->mem_alloc == 0) {
                fseek(p->rfile,fpak_info->offset,0);
                p->buffer = p->base;
                pcap_offline_read(p,1);
                fpak_info->pak = p->buffer;
                fpak_info->pak_len = p->cap_len;
        }
        pak_start = pak = fpak_info->pak;
        eth_hdr = (struct ethhdr *)pak;
        protocol = ntohs(eth_hdr->h_proto);
        pak += sizeof(struct ethhdr);
        hdrs_len += sizeof(struct ethhdr);
        for (;protocol == 0x8100;) {
                vlan_hdr = (struct vlan_802_1q *)pak;
                protocol = ntohs(vlan_hdr->protocol);
                pak += sizeof(struct vlan_802_1q);
                hdrs_len += sizeof(struct vlan_802_1q);
        }
        for (;protocol == 0x8847;) {
                hdrs_len += sizeof(struct mplshdr);
                if (pak_get_bits_uint32(*(uint32_t *)pak, 8, 1) == 1) {
                        protocol = 0x0800;
                        pak += sizeof(struct mplshdr);
                        break;
                }
                pak += sizeof(struct mplshdr);
        }
        if (protocol == 0x0800) {
		eth_hdr->h_proto = 0xDD86;
                ip_hdr = (struct iphdr *)pak;
                data_len = ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4);
                pak += (ip_hdr->ihl * 4);
                data = (uint8_t *)pak;
        	new_pak = (uint8_t *)malloc(hdrs_len + sizeof(struct ip6hdr) + 
				(fpak_info->pak_hdr.caplen - hdrs_len - ip_hdr->ihl * 4));
        	memcpy(new_pak, pak_start, hdrs_len);
		memset((void *)&ip6_hdr, 0, sizeof(ip6_hdr));
		ip6_hdr.next_header = ip_hdr->protocol;
		ip6_hdr.saddr.__in6_u.__u6_addr32[3] = ip_hdr->saddr;
		ip6_hdr.daddr.__in6_u.__u6_addr32[3] = ip_hdr->daddr;
		ip6_hdr.payload_length = htons(data_len);
		if (ip6_hdr.next_header == 0x11) {
			udp_hdr = (struct udphdr *)data;
			udp_hdr->check = 0;
			udp_hdr->check = chksum_v6 (data, data_len, &ip6_hdr.saddr, &ip6_hdr.daddr, ip6_hdr.next_header);
		} else if (ip6_hdr.next_header == 0x06) {
			tcp_hdr = (struct tcphdr *)data;
			tcp_hdr->check = 0;
			tcp_hdr->check = chksum_v6 (data, data_len, &ip6_hdr.saddr, &ip6_hdr.daddr, ip6_hdr.next_header);
		}
        	memcpy((new_pak + hdrs_len), (uint8_t *)&ip6_hdr, sizeof(struct ip6hdr));
        	memcpy((new_pak + hdrs_len + sizeof(struct ip6hdr)),
                data, (fpak_info->pak_hdr.caplen - hdrs_len - ip_hdr->ihl * 4));
        	if (fpak_info->mem_alloc == 1) {
                	free(fpak_info->pak);
        	}
        	fpak_info->mem_alloc = 1;
        	fpak_info->pak = new_pak;
        	fpak_info->pak_hdr.caplen = hdrs_len + sizeof(struct ip6hdr) + data_len;
        	fpak_info->pak_len = fpak_info->pak_hdr.len = fpak_info->pak_hdr.caplen;
        }
}

