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
	struct iphdr  *ip_hdr;
	struct udphdr *udp_hdr;
	struct tcphdr *tcp_hdr;
	struct icmphdr *icmp_hdr;
	struct arphdr  *arp_hdr;
	uint8_t *tptr = buf;

	eth_hdr = (struct ethhdr *)tptr;
	pak_info->src_mac = ether_to_str((uint8_t *)eth_hdr->h_source);
	pak_info->dst_mac = ether_to_str((uint8_t *)eth_hdr->h_dest);
	pak_info->eth_proto = ntohs(eth_hdr->h_proto);	
    	strcpy(pak_info->row_color, "#FFFFFF");
	strcpy(pak_info->info, " ");
	strcpy(pak_info->protocol, "UNKNOWN");


	tptr += sizeof(struct ethhdr);
	if (pak_info->eth_proto == 0x8100) {
		vlan_hdr = (struct vlan_802_1q *)tptr;
		pak_info->eth_proto = ntohs(vlan_hdr->protocol);
		tptr += sizeof(struct vlan_802_1q);
	} 
	if (pak_info->eth_proto == 0x8847) {
		tptr += sizeof(struct mplshdr);	
		pak_info->eth_proto = 0x0800;
	}
	if (pak_info->eth_proto == 0x0800) { /*ETH_P_IP*/
		ip_hdr = (struct iphdr *)tptr;
		pak_info->src_ip = ip_to_str((uint8_t *)&(ip_hdr->saddr));
		pak_info->dst_ip = ip_to_str((uint8_t *)&(ip_hdr->daddr));
		pak_info->proto  = ip_hdr->protocol;
		strcpy(pak_info->row_color, "#FFFFFF");
		strcpy(pak_info->protocol, "IP");
		if (pak_get_bits_uint16(ip_hdr->frag_off, 13, 1) == 1) {
			strcpy(pak_info->info, "Fragmented IP Packet");
			return 1;
		}
		if (pak_info->proto == 0x11) {
			tptr += (ip_hdr->ihl * 4);	
			udp_hdr = (struct udphdr *)tptr;
			strcpy(pak_info->protocol, "UDP");
			strcpy(pak_info->row_color, "#70DFFF");
			sprintf(pak_info->info, "%u > %u", ntohs(udp_hdr->source), ntohs(udp_hdr->dest));
		} else if (pak_info->proto == 0x06) {
			tptr += (ip_hdr->ihl * 4);
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
		} else if (pak_info->proto == 0x2f) {
			sprintf(pak_info->protocol, "GRE");
			sprintf(pak_info->info, " GRE Not Supported");
                } else if (pak_info->proto == 0x02) {
                        sprintf(pak_info->protocol, "IGMP");
                        sprintf(pak_info->info, "igmp packet");
			strcpy(pak_info->row_color, "#FFF3D5");
		} else {
			sprintf(pak_info->protocol, "0x%02x", ip_hdr->protocol);
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
	if (L3_proto == 0x0800) {            	/* Internet Protocol packet     */
		return (display_ipv4(pak));
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
display_L5(uint8_t *pak, uint16_t L5_proto)
{

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
	display_L5(hdr_cur, L5_proto);

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
	if (p_ref_proto == P_IPV4) {
		update_ipv4(value);

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
	struct iphdr *ip_hdr;
	struct tcphdr *tcp_hdr;
	struct udphdr *udp_hdr;
	uint8_t pak_reversed = 0;

        eth_hdr = (struct ethhdr *)fpak_curr_info->pak;
	if (eth_hdr->h_proto == 0x0008) {
		ip_hdr = (struct iphdr *)(fpak_curr_info->pak + sizeof(struct ethhdr));
		if ((ip_hdr->saddr == cur_pak_info.src_ip) || (ip_hdr->saddr == cur_pak_info.dst_ip) && 
				((ip_hdr->daddr == cur_pak_info.src_ip) || (ip_hdr->daddr == cur_pak_info.dst_ip))) {
			if (ip_hdr->saddr != cur_pak_info.src_ip) {
				pak_reversed = 1;
			}
			if (ip_hdr->protocol == 0x11) {
				udp_hdr = (struct udphdr *)(fpak_curr_info->pak + sizeof(struct ethhdr) + ip_hdr->ihl * 4);
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
				tcp_hdr = (struct tcphdr *)(fpak_curr_info->pak + sizeof(struct ethhdr) + ip_hdr->ihl * 4);
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
        struct iphdr *ip_hdr;
        struct tcphdr *tcp_hdr;
        struct udphdr *udp_hdr;
        uint8_t pak_reversed = 0;

        eth_hdr = (struct ethhdr *)fpak_curr_info->pak;
        if (eth_hdr->h_proto == 0x0008) {
                ip_hdr = (struct iphdr *)(fpak_curr_info->pak + sizeof(struct ethhdr));
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
                        }
                }
        }
	return (0);
}


