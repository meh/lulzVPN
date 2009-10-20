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

#ifndef _LNET_NETWORKING_H
#define _LNET_NETWORKING_H

/* Default listening port */
#define PORT			7890

#define CERT_FILE	"/etc/lulznet/cert.pem"
#define KEY_FILE	"/etc/lulznet/key"

extern SSL_CTX *ssl_client_ctx;
extern SSL_CTX *ssl_server_ctx;

/* global fd_set for select() */
extern fd_set master;

/* mutex used to prevent fd_db structure's modifies
   while select() main cycle is running */
extern pthread_t select_t;

/* Initialize ssl server's context */
void ssl_server_init ();

/* Initialize ssl client's context */
void ssl_client_init ();

/* Main server thread, accepting connection */
void *server_loop (void *arg);

/* return a int network ordered address from a string */
int lookup_address (char *address);

/* Function for connecting to a peer */
void peer_connect (int address, short port);

/* Function for disconnecting from a peer */
void disassociation_request (int fd);

/* Main forwarding function */
void *select_loop (void *arg);
inline void forward_to_tap (char *packet, u_int packet_len);
inline void forward_to_peer (char *packet, u_int packet_len);
void restart_select_loop();

/* handle cert verification */
int verify_ssl_cert (SSL * ssl);

/* check if we have to connect to another peer after handshake */
void *check_connections_queue (void *arg);

#endif
