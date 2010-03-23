/*
 * "networking.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

#ifndef _LVPN_NETWORKING_H
#define _LVPN_NETWORKING_H

#include "lulzvpn.h"
#include "peer.h"
#include "packet.h"

const short port = 7890;
const int addressLenght= 16;
const int maxAcceptedConnections = 128;
#define CERT_FILE "/etc/lulzvpn/cert.pem"
#define KEY_FILE "/etc/lulzvpn/key"

typedef struct PeerAddrPort {
     uInt address;
     uShort port;
} PeerAddrPort;

namespace Network
{

namespace Client
{

extern SSL_CTX *TcpSSLCtx;
extern SSL_CTX *UdpSSLCtx;

/* Initialize ssl client's context */
void sslInit ();

void* PeerConnectThreadWrapper (void *stuff);

/* Function for connecting to a peer */
void PeerConnect (int address, short port);

}

namespace Server
{

extern SSL_CTX *TcpSSLCtx;
extern SSL_CTX *UdpSSLCtx;

extern pthread_t ServerLoopT;

/* mutex used to prevent fd_db structure's modifies
   while select() main cycle is running */
extern pthread_t select_t;

/* Initialize ssl server's context */
void sslInit ();

/* Main server thread, accepting connection */
void *ServerLoop (void *arg);

void UdpRecverInit ();

}

/* Main forwarding function */
void ForwardToTap (Packet::DataPacket *packet, Peers::Peer *src);
void ForwardToPeer (Packet::DataPacket *packet, uChar localId);

void HandleClosingConnection(Peers::Peer *peer, int *flag);
void HandleNewPeerNotify(Packet::CtrlPacket *packet);

/* return a int network ordered address from a string */
int LookupAddress (std::string address);

/* Function for disconnecting from a peer */
void disassociation_request (Peers::Peer *peer);

/* handle cert verification */
int VerifySslCert (SSL *ssl);

/* check if we have to connect to another peer after handshake */
void *CheckConnectionsQueue (void *arg);

void UpdateNonListeningPeer(std::string user, int address);
}

#endif

