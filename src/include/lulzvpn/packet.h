/*
 * "packet.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
 *
 * lulzVPN is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * lulzVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */

#ifndef _LVPN_PACKET_H
#define _LVPN_PACKET_H

#include "lulzvpn.h"
#include "protocol.h"

/* Total packet length */

const int ETH_ADDR_LEN = 6;
const int ETH_HDR_LEN = 14;


namespace Packet
{

const unsigned int PacketHdrLen = 1;
const unsigned int PacketPldLen = 4096;
const unsigned int PacketTotLen = PacketHdrLen + PacketPldLen;

struct CtrlPacket
{
  unsigned char buffer[PacketTotLen];
  int length;
} __attribute__ ((packed));

struct DataPacket
{
  unsigned char buffer[PacketTotLen];
  int length;
} __attribute__ ((packed));

/* MAC header */
struct macHeader
{
  uChar dst_adr[ETH_ADDR_LEN];
  uChar src_adr[ETH_ADDR_LEN];
  u_short eth_type;
} __attribute__ ((packed));

/* arp header */
struct arpHeader
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
struct ipHeader
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

CtrlPacket *BuildDisassociationPacket(); 
CtrlPacket *BuildNewPeerNotifyPacket (std::string user, int address);

/* return int network ordered address of the packet dest */
uInt GetDestinationIp (DataPacket *packet);
}

#endif

