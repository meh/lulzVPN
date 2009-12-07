/*
 * "protocol.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

#ifndef _LNET_PROTOCOL_H
#define _LNET_PROTOCOL_H

#define DATA_PACKET		'\x00'
#define CONTROL_PACKET		'\x01'

#define NEW_PEER		0x01
#define AUTH_SERVICE		0x02

#define CLOSE_CONNECTION	'\x01'

typedef struct
{
  std::string * user;
  int *address;

  int count;
} userLsT;

typedef struct
{
  int count;

  std::string *device;
  int *address;
  int *netmask;
  int *network;
} netLsT;

typedef struct
{
  std::string peer_username;
  userLsT userLs;
  netLsT netLs;
} hsOptT;

namespace Protocol
{

/* Send and recv banner */
void SendBanner (int fd);
void RecvBanner (int fd);

namespace server
{
int Handshake (SSL * ssl, hsOptT * hsOpt);
int LnUserExchange (SSL * ssl, hsOptT * hsOpt);
int LnAuth (SSL * ssl, hsOptT * hsOpt);
}

namespace client
{
/* peer and server handshake */
int Handshake (SSL * ssl, hsOptT * hsOpt);
int LnUserExchange (SSL * ssl, hsOptT * hsOpt);
int LnAuth (SSL * ssl);
}

/* Networks exchange */
int LnSendNetworks (SSL * ssl, hsOptT * hsOpt);
int LnRecvNetworks (SSL * ssl, hsOptT * hsOpt);

/* User exchange */
int LnSendUserlist (SSL * ssl);
int LnRecvUserlist (SSL * ssl, hsOptT * hsOpt);

/* Return a list with all the users connected */
userLsT GetUserlist ();
}
#endif
