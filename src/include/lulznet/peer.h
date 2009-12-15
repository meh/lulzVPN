/*
 * "peer.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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
#include "packet_buffer.h"

#ifndef _LNET_PEER_H
#define _LNET_PEER_H

#define PEER_ACTIVE	1
#define PEER_CLOSING	2

#define INCOMING_CONNECTION	1
#define	OUTGOING_CONNECTION	2

namespace Peers
{

/* related file descriptor */
/* peer state (active, closing, ...) */
/* incoming, outcoming */
/* remote peer username and address */
/* peer's lulz device info */
/* Register a new peer in the peer_db structure
 * set fd value, flags, ssl relative pointer and other info */
/* Remove peer registration from peer_db */

class Peer
{
private:
  int _fd;
  SSL *_ssl;
  char _state;
  char _type;
  std::string _user;
  int _address;
  int _virtualAddress;
  networkListT _nl;

public:
  Peer (int fd, SSL * ssl, std::string user, int address, networkListT nl,
        char type);
  ~Peer ();
  bool operator>> (Network::Packet * packet);
  bool operator<< (Network::Packet * packet);

  bool isRoutableAddress(int address);
  bool isActive();
  bool isReadyToRead(fd_set *rdSel);
  void setClosing();
  void Disassociate();

public:
  int fd();
  std::string user();
  int address();
  networkListT nl();
};

extern Peer *db[MAX_PEERS];
extern pthread_mutex_t db_mutex;

extern int count;
extern int conections_to_peer;
extern int maxFd;

/* set global var max_peer_fd to proper value (we use it with select() ) */
void SetMaxFd ();

/* Check for non active peer and reomve them */
void FreeNonActive ();

/* Delete empty entry */
void RebuildDb ();

/* Check if user is connected */
int UserIsConnected (std::string user);
}

#endif
