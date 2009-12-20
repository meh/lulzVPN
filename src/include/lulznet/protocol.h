/*
 * "protocol.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
 *
 * LulzNet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * LulzNet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
*/

#include <vector>

#ifndef _LNET_PROTOCOL_H
#define _LNET_PROTOCOL_H

#define DATA_PACKET			'\x00'

#define CONTROL_PACKET			'\x01'
#define CLOSE_CONNECTION		'\x01'

#define USER_CONNECTED			'\x00'
#define USER_NOT_CONNECTED		'\x01'

#define NETWORK_NOT_ALLOWED		'\x00'
#define NETWORK_ALLOWED			'\x01'

#define AUTHENTICATION_FAILED		'\x00'
#define AUTHENTICATION_SUCCESSFULL 	'\x01'

#define MAX_NETWORKNAME_LEN		16
#define MAX_USERNAME_LEN		16
#define MAX_PASSWORD_LEN		32

typedef struct
{
  std::vector<std::string> user;
  std::vector<int> address;
} userListT;

typedef struct
{
  std::vector<std::string> NetworkName;
  std::vector<int> address;
  std::vector<int> netmask;
  std::vector<int> network;

} networkListT;

typedef struct
{
  std::string peer_username;
  userListT userLs;

  networkListT remoteNets;
  networkListT allowedNets;
} HandshakeOptionT;

namespace Protocol
{

/* Send and recv banner */
void SendBanner (int fd);
void RecvBanner (int fd);

namespace Server
{
int Handshake (SSL * ssl, HandshakeOptionT * hsOpt);
int LulzNetUserExchange (SSL * ssl, HandshakeOptionT * hsOpt);
int LulzNetAuth (SSL * ssl, HandshakeOptionT * hsOpt);
}

namespace Client
{
/* peer and server handshake */
int Handshake (SSL * ssl, HandshakeOptionT * hsOpt);
int LulzNetUserExchange (SSL * ssl, HandshakeOptionT * hsOpt);
int LulzNetAuth (SSL * ssl);
}

/* Networks exchange */
int LulzNetSendNetworks (SSL * ssl, HandshakeOptionT * hsOpt);
int LulzNetReciveNetworks (SSL * ssl, HandshakeOptionT * hsOpt);

/* User exchange */
int LulzNetSendUserlist (SSL * ssl);
int LulzNetReciveUserlist (SSL * ssl, HandshakeOptionT * hsOpt);

/* Return a list with all the users connected */
userListT GetUserlist ();
}
#endif
