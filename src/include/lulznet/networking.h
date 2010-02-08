/*
 * "networking.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

#include "peer.h"

#ifndef _LNET_NETWORKING_H
#define _LNET_NETWORKING_H

/* Default listening port */
const short port = 7890;
const int addressLenght= 16;
const int maxAcceptedConnections = 128;

#define CERT_FILE       "/etc/lulznet/cert.pem"
#define KEY_FILE        "/etc/lulznet/key"

typedef struct PeerAddrPort {
     uInt address;
     uShort port;
} PeerAddrPort;

namespace Network
{

extern fd_set master;

namespace Client
{

extern SSL_CTX *sslCTX;
/* Initialize ssl client's context */
void sslInit ();

void* PeerConnectThreadWrapper (void *stuff);

/* Function for connecting to a peer */
void PeerConnect (int address, short port);

}

namespace Server
{

extern SSL_CTX *sslCTX;

/* mutex used to prevent fd_db structure's modifies
   while select() main cycle is running */
extern pthread_t select_t;

/* Initialize ssl server's context */
void sslInit ();

/* Main server thread, accepting connection */
void *ServerLoop (void *arg);


/* Main forwarding function */
void *SelectLoop (void *arg);
inline void ForwardToTap (Packet::Packet *packet, Peers::Peer *src);
inline void ForwardToPeer (Packet::Packet *packet, uChar localId);
void RestartSelectLoop ();
}

void HandleClosingConnection(Peers::Peer *peer, int *flag);
void HandleNewPeerNotify(Packet::Packet *packet);

/* return a int network ordered address from a string */
int LookupAddress (std::string address);

/* Function for disconnecting from a peer */
void disassociation_request (Peers::Peer *peer);

/* handle cert verification */
int VerifySslCert (SSL * ssl);

/* check if we have to connect to another peer after handshake */
void *CheckConnectionsQueue (void *arg);

void UpdateNonListeningPeer(std::string user, int address);
}

#endif
