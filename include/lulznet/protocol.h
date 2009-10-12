/*
 * "protocol.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

/* TODO: dinamic alloc && mem leak fix */

#define DATA_PACKET		'\x00'
#define CONTROL_PACKET		'\x01'

#define NEW_PEER		0x01
#define AUTH_SERVICE		0x02

#define CLOSE_CONNECTION	'\x01'

/* Send and recv banner */
void send_banner (int fd);
void recv_banner (int fd);

/* peer and server handshake */
handshake_opt_t *peer_handshake (SSL * ssl);
handshake_opt_t *server_handshake (SSL * ssl);

int lulznet_server_user_exchange (SSL * ssl, handshake_opt_t * hs_opt);
int lulznet_client_user_exchange (SSL * ssl, handshake_opt_t * hs_opt);

int lulznet_server_auth (SSL * ssl, handshake_opt_t * hs_opt);
int lulznet_client_auth (SSL * ssl);

int lulznet_send_network (SSL * ssl, handshake_opt_t * hs_opt);
int lulznet_recv_network (SSL * ssl, handshake_opt_t * hs_opt);

int lulznet_send_userlist (SSL * ssl);
int lulznet_recv_userlist (SSL * ssl, handshake_opt_t * hs_opt);


/* Return a list with all the users connected */
user_list_t *get_userlist ();
