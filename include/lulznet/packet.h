/*
 * "packet.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
 *
 * lulzNet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * lulzNet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
*/

#ifndef _LNET_PACKET_H
#define _LNET_PACKET_H

#define ETH_ADDR_LEN 6
#define ETH_HDR_LEN  14

/* MAC header */
typedef struct eth_header {
     u_char dst_adr[ETH_ADDR_LEN];
     u_char src_adr[ETH_ADDR_LEN];
     u_short eth_type;
} __attribute__((packed)) eth_header;

/* arp header */
typedef struct arp_header {
     u_short hw_type;
     u_short proto_type;
     u_char hw_size;
     u_char proto_size;
     u_short opcode;
     u_char src_mac_adr[ETH_ADDR_LEN];
     u_int src_ip_adr;
     u_char dst_mac_adr[ETH_ADDR_LEN];
     u_int dst_ip_adr;     
} __attribute__((packed)) arp_header;

/* ip header */
typedef struct ip_header {
     u_char ver_and_hdr_len;
     u_char tos;
     u_short len;
     u_short id;
     u_short frag_offset;
     u_char ttl;
     u_char type;
     u_short checksum;
     u_int src_adr;
     u_int dst_adr;
} ip_header;

/* return int network ordered address of the packet dest */
u_int get_destination_ip(char *packet);

#endif
