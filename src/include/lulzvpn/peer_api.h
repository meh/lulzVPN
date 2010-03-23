/*
 * "peer_api.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

#ifndef _LVPN_PEER_API_H
#define _LVPN_PEER_API_H

#include "peer.h"

const bool accepted = 0;
const bool connected = 1;

namespace Peers
{

extern std::vector<Peer *> db;
extern pthread_mutex_t db_mutex;

extern int maxTcpFd;
extern int maxUdpFd;

void Register(Peer *p);

/* set global var maxFd to proper value (we use it with select() ) */
void SetMaxTcpFd ();
void SetMaxUdpFd ();

/* Check for non active peer and reomve them */
void FreeNonActive ();

/* Check if user is connected */
int UserIsConnected (std::string user);
}

#endif
