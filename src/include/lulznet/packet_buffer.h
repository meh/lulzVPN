/*
 * "packet_buffer.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

#include "protocol.h"

#ifndef LNET_PACKET_BUFFER
#define LNET_PACKET_BUFFER

/* Header length */
#define PCKT_HDR_LEN 1
/* Payload length */
#define PCKT_PLD_LEN 4096

/* Total packet length */
#define PCKT_TOT_LEN PCKT_HDR_LEN + PCKT_PLD_LEN

namespace Network
{

struct Packet
{
  unsigned char buffer[PCKT_TOT_LEN];
  int length;
} __attribute__ ((packed));
}

#endif
