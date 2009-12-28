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

#include "packet_buffer.h"

#ifndef _LNET_PACKET_H
#define _LNET_PACKET_H

#define ETH_ADDR_LEN 6
#define ETH_HDR_LEN  14

namespace PacketInspection
{

/* MAC header */
struct eth_header
{
  uChar dst_adr[ETH_ADDR_LEN];
  uChar src_adr[ETH_ADDR_LEN];
  u_short eth_type;
} __attribute__ ((packed));

/* arp header */
struct arp_header
{
  u_short hw_type;
  u_short proto_type;
  uChar hw_size;
  uChar proto_size;
  u_short opcode;
  uChar src_mac_adr[ETH_ADDR_LEN];
  uInt src_ip_adr;
  uChar dst_mac_adr[ETH_ADDR_LEN];
  uInt dst_ip_adr;
} __attribute__ ((packed));

/* ip header */
struct ip_header
{
  uChar ver_and_hdr_len;
  uChar tos;
  u_short len;
  u_short id;
  u_short frag_offset;
  uChar ttl;
  uChar type;
  u_short checksum;
  uInt src_adr;
  uInt dst_adr;
} __attribute__ ((packed));

/* return int network ordered address of the packet dest */
uInt GetDestinationIp (Network::Packet *packet);

}

#endif
