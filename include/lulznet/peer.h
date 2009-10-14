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

#define ACTIVE_PEER	0x00000001

extern peer_handler_t peer_db[MAX_PEERS];

/* search first free position in peer_db */
int get_first_free_peer_db_position ();

/* return max peer file descriptor (we use it with select() ) */
int get_max_peer_fd ();

/* Register a new peer in the peer_db structure
 * set fd value, flags, ssl relative pointer and other info */
void register_peer (int fd, SSL * ssl, char *user, int address, network_list_t * nl, char flags);

/* Check if argument is registerd as fd */
int is_active_peer_fd (int fd);

/* Mark a peer as non active */
void set_non_active_peer (int fd);

/* Remove peer registration from peer_db */
void deregister_peer (int fd);

/* Check for non active peer and reomve them */
void *free_non_active_peer (void *arg __attribute__((unused)));

peer_handler_t *get_fd_related_peer (int fd);

/* Return the arg associated SSL pointer */
SSL *get_relative_ssl (int fd);

/* return remote peer address fd */
int get_peer_relative_address (int fd);

/* return remote peer's tap network and netmask */

/* Return user that use that socket */
char *get_peer_relative_peer_user (int fd);

network_list_t *get_peer_relative_network_list (int fd);

/* Check if user is connected */
int user_is_connected (char *user);
