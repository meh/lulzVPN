/*
 * "peer.cpp" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

#include <lulzvpn/lulzvpn.h>
#include <lulzvpn/log.h>
#include <lulzvpn/packet.h>
#include <lulzvpn/networking.h>

Packet::CtrlPacket *
Packet::BuildDisassociationPacket () 
{
  CtrlPacket *packet;

  packet = new CtrlPacket;
  packet->buffer[0] = closeConnection;

  packet->length = 1;

  return packet;
}

Packet::CtrlPacket *
Packet::BuildNewPeerNotifyPacket (std::string user, int address)
{
  CtrlPacket *packet;

  packet = new CtrlPacket;
  packet->buffer[0] = newPeerNotify;

  sprintf((char *) packet->buffer + 1, "%s ", user.c_str()); 
  memcpy(packet->buffer + 1 + user.length() + 1, (char *) &address , 4);

  packet->length = 1 + user.length() + 1 + 4;

  return packet;
}

uInt
Packet::GetDestinationIp (Packet::DataPacket *packet)
{
  macHeader *macHdr;
  arpHeader *arpHdr;
  ipHeader *ipHdr;
  uInt address;
  u_short protocol;

#ifdef DEBUG
  char p_addr[addressLenght];
#endif

  macHdr = (macHeader *)(packet->buffer + 1);
  protocol = macHdr->eth_type;
  protocol = ntohs(protocol);

  if (protocol == 0x0806) {
    /*arp packet */

    arpHdr = (arpHeader *)(packet->buffer + ETH_HDR_LEN + 1);
    address = arpHdr->dst_ip_adr;

#ifdef DEBUG
    inet_ntop(AF_INET, &address, p_addr, addressLenght);
    Log::Debug3("\tarp packet, dst: %s", p_addr);
#endif

  }
  else if (protocol == 0x0800) {
    /* ip packet */

    ipHdr = (ipHeader *)(packet->buffer + ETH_HDR_LEN + 1);
    address = ipHdr->dst_adr;

#ifdef DEBUG
    inet_ntop(AF_INET, &address, p_addr, addressLenght);
    Log::Debug3("\tip packet, dst: %s", p_addr);
#endif
  }
  else
    /*TODO: add more protocol, for now
       we assume it's a faggot packet
       and we return 0 */
    address = 0;

  return address;
}

