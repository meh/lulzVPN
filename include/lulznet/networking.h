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

/* Default listening port */
#define PORT			7890

#define CERT_FILE	"/etc/lulznet/cert.pem"
#define KEY_FILE	"/etc/lulznet/key"

/* mutex used to prevent fd_db structure's modifies
   while select() main cycle is running */
extern pthread_mutex_t select_mutex;

extern pthread_t select_t;

extern SSL_CTX *ssl_client_ctx;
extern SSL_CTX *ssl_server_ctx;

/* global fd_set for select() */
extern fd_set master;

/* Initialize ssl server's context */
void ssl_server_init ();

/* Initialize ssl client's context */
void ssl_client_init ();

/* Main server thread, accepting connection */
void *server_loop (void *arg);

int lookup_address (char *address);

/* Function to connect to a peer */
void peer_connect (int address, short port);

/* Function to disconnect from a peer */
void peer_disconnect (int fd);

/* Main forwarding function */
void *select_loop (void *arg);
inline void forward_to_tap (char *packet, u_int packet_len, int current_fd, int max_fd);
inline void forward_to_peer (char *packet, u_int packet_len, int current_fd, int max_fd);

/* handle cert verification */
int verify_ssl_cert (SSL * ssl);

/* check if we have to connect to another peer after handshake */
void *check_connections_queue (void *arg);
