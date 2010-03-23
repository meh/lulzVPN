/*
 * "peer.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

#ifndef _LVPN_PEER_H
#define _LVPN_PEER_H

#include "lulzvpn.h"
#include "packet.h"

namespace Peers {

struct Connection {
     SSL *tcpSSL;
     SSL *udpSSL;
     int tcpSd;
     int udpSd;
};

class Peer
{

/* related file descriptor */
int _tcpSd;
int _udpSd;

SSL *_tcpSSL;
SSL *_udpSSL;

/* peer state (active, closing, ...) */
char _state;

char _listeningStatus;

/* incoming, outcoming */
bool _connType;

/* remote peer username and address */
std::string _user;
int _address;
int _virtualAddress;
std::vector<networkT> _nl;

public:
Peer (Connection con, std::string user, int address, std::vector<networkT> nl, char listenStat, bool connType);
~Peer ();

bool operator>> (Packet::CtrlPacket *packet);
bool operator<< (Packet::CtrlPacket *packet);

bool operator>> (Packet::DataPacket *packet);
bool operator<< (Packet::DataPacket *packet);
Packet::DataPacket * decryptRawSSLPacket(Packet::DataPacket *encPacket);

bool isRoutableAddress(int address);
bool isListening();
bool isActive();
bool isReadyToReadFromCtrlChannel(fd_set *rdSel);
bool isReadyToReadFromDataChannel(fd_set *rdSel);
bool connType();
void setClosing();
void Disassociate();

public:
int tcpSd();
int udpSd();
std::string user();
int address();
const std::vector<networkT>& nl();
};
}
#endif

