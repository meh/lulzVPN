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

#ifndef _LNET_PEER_H
#define _LNET_PEER_H

#define PEER_ACTIVE	1
#define PEER_CLOSING	2
#define PEER_STOPPED	4

#define INCOMING_CONNECTION	1
#define	OUTGOING_CONNECTION	2

/* This struct holds remote peers informations */
typedef struct
{
  /* related file descriptor */
  int fd;
  SSL *ssl;

  /* peer state (active, closing, ...) */
  char state;

  /* incoming, outcoming */
  char type;

  /* remote peer username and address */
  char *user;
  int address;

  /* peer's lulz device info */
  net_ls_t *nl;

} peer_handler_t;

extern peer_handler_t peer_db[MAX_PEERS];
extern pthread_mutex_t peer_db_mutex;

extern int peer_count;
extern int connections_to_peer;
extern int max_peer_fd;

/* set global var max_peer_fd to proper value (we use it with select() ) */
void set_max_peer_fd ();

/* Register a new peer in the peer_db structure
 * set fd value, flags, ssl relative pointer and other info */
peer_handler_t *register_peer (int fd, SSL * ssl, char *user, int address, net_ls_t * nl, char type);

/* Remove peer registration from peer_db */
void deregister_peer (int fd);

/* Check for non active peer and reomve them */
void free_non_active_peer ();

/* Delete empty entry */
void rebuild_peer_db ();

/* return the peer associated with an fd */
peer_handler_t *get_fd_related_peer (int fd);

/* Check if user is connected */
int user_is_connected (char *user);

#endif
