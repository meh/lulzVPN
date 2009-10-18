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

#define ACTIVE	0x01
#define CLOSING	0x02

extern peer_handler_t peer_db[MAX_PEERS];
extern pthread_mutex_t peer_db_mutex;

extern int peer_count;
extern int max_peer_fd;

/* set global var max_peer_fd to proper value (we use it with select() ) */
void set_max_peer_fd ();

/* Register a new peer in the peer_db structure
 * set fd value, flags, ssl relative pointer and other info */
peer_handler_t *register_peer (int fd, SSL * ssl, char *user, int address, net_ls_t * nl);

/* Remove peer registration from peer_db */
void deregister_peer (int fd);

/* Check for non active peer and reomve them */
void *free_non_active_peer (void *arg __attribute__((unused)));

/* return the peer associated with an fd */
peer_handler_t *get_fd_related_peer (int fd);

/* Check if user is connected */
int user_is_connected (char *user);
