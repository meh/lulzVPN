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

const char dataPacket = '\x00';
const char controlPacket = '\x01';
const char closeConnection = '\x01';
const char userNotConnected ='\x00';
const char userConnected = '\x01';
const char networkNotAllowed ='\x00';
const char networkAllowed = '\x01';
const char AUTHENTICATION_FAILED = '\x00';
const char AUTHENTICATION_SUCCESSFULL = '\x01';
const int MAX_NETWORKNAME_LEN = 16;
const int MAX_USERNAME_LEN = 16;
const int MAX_PASSWORD_LEN = 32;

const char active = 0;
const char closing = 1;

typedef struct
{
  std::string user;
  int address;
} userT;

typedef struct
{
  std::string networkName;
  uChar remoteId;
  uChar localId;

  int address;
  int netmask;
  int network;

} networkT;

typedef struct
{
  std::string peer_username;
  std::vector<userT> userLs;

  std::vector<networkT> remoteNets;
  std::vector<networkT> allowedNets;
} HandshakeOptionT;

namespace Protocol
{

/* Send and recv banner */
void SendBanner (int fd);
void RecvBanner (int fd);

namespace Server
{
bool Handshake (SSL * ssl, HandshakeOptionT * hsOpt);
bool LulzNetUserExchange (SSL * ssl, HandshakeOptionT * hsOpt);
bool LulzNetAuth (SSL * ssl, HandshakeOptionT * hsOpt);
}

namespace Client
{
/* peer and server handshake */
bool Handshake (SSL * ssl, HandshakeOptionT * hsOpt);
bool LulzNetUserExchange (SSL * ssl, HandshakeOptionT * hsOpt);
bool LulzNetAuth (SSL * ssl);
}

/* Networks exchange */
bool LulzNetSendNetwork (SSL * ssl, networkT net);
bool LulzNetRecvNetwork (SSL *ssl, networkT *net, std::vector<networkT> allowedNets);

bool LulzNetSendNetworks (SSL * ssl, HandshakeOptionT * hsOpt);
bool LulzNetReciveNetworks (SSL * ssl, HandshakeOptionT * hsOpt);

/* User exchange */
bool LulzNetSendUser (SSL *ssl, userT user);
bool LulzNetRecvUser (SSL *ssl, userT *user);

bool LulzNetSendUserlist (SSL * ssl);
bool LulzNetReciveUserlist (SSL * ssl, HandshakeOptionT * hsOpt);

/* Return a list with all the users connected */
std::vector<userT> GetUserlist ();
}
#endif
