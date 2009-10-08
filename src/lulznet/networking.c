/*
 * "networking.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

#include <lulznet/lulznet.h>
#include <lulznet/types.h>

#include <lulznet/auth.h>
#include <lulznet/config.h>
#include <lulznet/log.h>
#include <lulznet/networking.h>
#include <lulznet/peer.h>
#include <lulznet/protocol.h>
#include <lulznet/tap.h>
#include <lulznet/xfunc.h>

void
ssl_server_init ()
{
  ssl_server_ctx = SSL_CTX_new (SSLv23_server_method ());

  if (!ssl_server_ctx)
    fatal ("Failed to do SSL CTX new");

  debug2 ("Loading SSL certificate");
  if (SSL_CTX_use_certificate_file
      (ssl_server_ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0)
    fatal ("Failed to load SSL certificate %s", CERT_FILE);

  debug2 ("Loading SSL private key");
  if (SSL_CTX_use_PrivateKey_file (ssl_server_ctx, KEY_FILE, SSL_FILETYPE_PEM)
      <= 0)
    fatal ("Failed to load SSL private key %s", KEY_FILE);
}

void
ssl_client_init ()
{
  ssl_client_ctx = SSL_CTX_new (SSLv23_client_method ());
}

void *
server_loop ()
{

  int listen_sock, peer_sock;
  SSL *peer_ssl;
  struct sockaddr_in server, peer;
  int on = 1;
  socklen_t addr_size;
  char peer_address[ADDRESS_LEN];
  pthread_t connect_queue_t;
  handshake_opt_t *handshake_opt;

  if ((listen_sock = socket (PF_INET, SOCK_STREAM, 0)) == -1)
    fatal ("cannot create socket");

  debug1 ("listen_sock (fd %d) created", listen_sock);
  if (setsockopt (listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) ==
      -1)
    error ("setsockopt SO_REUSEADDR: %s", strerror (errno));


  server.sin_family = AF_INET;
  server.sin_port = htons (opt.binding_port);
  server.sin_addr.s_addr = INADDR_ANY;	/*(server_opt->binding_address); */
  memset (&(server.sin_zero), '\0', 8);

  debug1 ("Binding port %d", PORT);
  if (bind
      (listen_sock, (struct sockaddr *) &server,
       sizeof (struct sockaddr)) == -1)
    fatal ("cannot binding to socket");

  info ("Listening");
  if (listen (listen_sock, MAX_PEERS) == -1)
    fatal ("cannot listen");

  addr_size = sizeof (struct sockaddr_in);

  /* @TODO while(available_connection()) else sleep && goto! */
  while (1)
    {
      if ((peer_sock =
	   accept (listen_sock, (struct sockaddr *) &peer, &addr_size)) == -1)
	fatal ("cannot accept");

      send_banner (peer_sock);

      if ((peer_ssl = SSL_new (ssl_server_ctx)) != NULL)
	{
	  SSL_set_fd (peer_ssl, peer_sock);

	  debug2 ("SSL Handshake");
	  if (SSL_accept (peer_ssl) > 0)
	    if ((handshake_opt = server_handshake (peer_ssl)))
	      {
		/* All good! Now we add routing rules */
		add_user_routing (handshake_opt->peer_username,
				  handshake_opt->network_list);

		register_peer (peer_sock, peer_ssl,
			       handshake_opt->peer_username,
			       peer.sin_addr.s_addr,
			       handshake_opt->network_list,
			       handshake_opt->flags);
		inet_ntop (AF_INET, &peer.sin_addr.s_addr, peer_address,
			   ADDRESS_LEN);
		info ("Connection accepted from %s (fd %d)", peer_address,
		      peer_sock);

		pthread_create (&connect_queue_t, NULL,
				check_connections_queue,
				handshake_opt->user_list);
		pthread_join (connect_queue_t, NULL);
	      }
	    else
	      {
		error ("Cannot comlpete lulznet handshake");
		deregister_peer (peer_sock);
	      }
	  else
	    {
	      error ("Cannot complete SSL handshake");
	      deregister_peer (peer_sock);
	    }
	}
    }
  free (handshake_opt);
}

int
lookup_address (char *address)
{

  struct hostent *host_info;
  char p_address[16];

  debug1 ("Looking up client %s", address);
  host_info = gethostbyname (address);

  if (host_info == NULL)
    {
      error ("Cannot lookup hostname", 1);
      return 0;
    }

  /* FIXME: try to do something only with a cast */
  inet_ntop (AF_INET, host_info->h_addr, p_address, 16);
  return xinet_pton (p_address);

}

void
peer_connect (int address, short port)
{

  struct sockaddr_in peer;
  int peer_sock;
  SSL *peer_ssl;
  handshake_opt_t *handshake_opt;
  pthread_t connect_queue_t;

  if ((peer_sock = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
      error ("cannot create socket", 1);
      return;
    }

  debug2 ("peer_sock (fd %d) created", peer_sock);

  peer.sin_family = AF_INET;
  peer.sin_port = htons (port ? port : PORT);
  peer.sin_addr.s_addr = address;
  memset (&(peer.sin_zero), '\0', 8);

  if (connect (peer_sock, (struct sockaddr *) &peer, sizeof (peer)) == -1)
    {
      error ("Cannot connect", 1);
      return;
    }

  recv_banner (peer_sock);

  peer_ssl = SSL_new (ssl_client_ctx);
  SSL_set_fd (peer_ssl, peer_sock);

  debug2 ("SSL Handshake");
  if (SSL_connect (peer_ssl) > 0)
    if (verify_ssl_cert (peer_ssl))
      if ((handshake_opt = peer_handshake (peer_ssl)))
	{
	  add_user_routing (handshake_opt->peer_username,
			    handshake_opt->network_list);

	  register_peer (peer_sock, peer_ssl, handshake_opt->peer_username,
			 address, handshake_opt->network_list,
			 handshake_opt->flags);
	  info ("Connected");

	  pthread_create (&connect_queue_t, NULL, check_connections_queue,
			  handshake_opt->user_list);
	  pthread_join (connect_queue_t, NULL);
	}
      else
	{
	  error ("Cannoc complete lulznet handshake");
	  deregister_peer (peer_sock);
	}
    else
      {
	error ("Cannot verify host identity");
	deregister_peer (peer_sock);
      }
  else
    {
      error ("Cannot complete SSL handshake");
      deregister_peer (peer_sock);
    }
  free (handshake_opt);		/* TODO: and all internal struct */
}

void
peer_disconnect (int fd)
{
  char packet[3];
  peer_handler_t *peer;

  peer = get_fd_related_peer (fd);
  if (peer != NULL)
    {

      sprintf ((char *) packet, "%c%c", CONTROL_PACKET, CLOSE_CONNECTION);
      xSSL_write (peer->ssl, packet, 2, "disconnection packet");
      deregister_peer (fd);
    }
}

void *
select_loop ()
{
  char packet_buffer[4096];
  int ret;
  fd_set read_select;
  int max_fd;
  int max_peer_fd;
  int max_tap_fd;
  int fd;
  int rd_len;

  pthread_t free_fd_t;

  peer_handler_t *peer;
  tap_handler_t *tap;

  int dont_close_flag = 1;
  int free_fd_flag = 0;

  while (dont_close_flag)
    {

      read_select = master;

      max_peer_fd = get_max_peer_fd ();
      max_tap_fd = get_max_tap_fd ();

      if (max_peer_fd > max_tap_fd)
	max_fd = max_peer_fd;
      else
	max_fd = max_tap_fd;

      ret = select (max_fd + 1, &read_select, NULL, NULL, NULL);

      /* We block the forwarding cycle */
      pthread_mutex_lock (&select_mutex);

      if (ret == -1)
	fatal ("Select error");
      else
	{
	  /* 0,1 and 2 are stdin-out-err and we don't care about them */
	  for (fd = 3; fd <= max_fd; fd++)
	    {
	      peer = get_fd_related_peer (fd);
	      if (peer != NULL)
		if (peer->flags & ACTIVE_PEER)
		  if (FD_ISSET (peer->fd, &read_select))
		    {
		      /* Read from it */
		      rd_len =
			xSSL_read (peer->ssl, packet_buffer, 4095,
				   "forwarding data");
		      debug3 ("sock_fd %d (0x%x ssl): read %d bytes packet",
			      peer->fd, peer->ssl, rd_len);

		      switch (packet_buffer[0])
			{
			case DATA_PACKET:
			  forward_to_tap (packet_buffer, rd_len, peer->fd,
					  max_fd);
			  break;
			case CONTROL_PACKET:
			  if (packet_buffer[1] == CLOSE_CONNECTION)
			    {
			      debug3 ("control_packet: closing connection");
			      free_fd_flag = 1;
			      /* set non active */
			      if (peer->flags & ACTIVE_PEER)
				peer->flags ^= ACTIVE_PEER;
			    }
			  break;
			}
		    }
	    }

	  for (fd = 3; fd <= max_fd; fd++)
	    {
	      tap = get_fd_related_tap (fd);
	      if (tap != NULL)
		if (tap->flags & ACTIVE_TAP)
		  if (FD_ISSET (tap->fd, &read_select))
		    {
		      rd_len = read (tap->fd, packet_buffer + 1, 4095);
		      debug3 ("tap_fd %d: read %d bytes packet", tap->fd,
			      rd_len);

		      /* TODO:
		         add cool routing (packet inspection etc) */
		      forward_to_peer (packet_buffer, rd_len, tap->fd,
				       max_fd);

		    }
	    }
	}

      /* When the cycle is end functions can modify the fd_db structure */
      pthread_mutex_unlock (&select_mutex);

      if (free_fd_flag)
	{
	  pthread_create (&free_fd_t, NULL, free_non_active_peer, NULL);
	  /* TODO: check this */
	  pthread_join (free_fd_t, NULL);

	}
    }
  return NULL;
}

inline void
forward_to_tap (char *packet, u_int packet_len, int current_fd, int max_fd)
{

  int fd;
  tap_handler_t *tap;

  debug3 ("data_packet");
  for (fd = 3; fd <= max_fd; fd++)
    {
      tap = get_fd_related_tap (fd);
      if (tap != NULL)
	if (tap->flags & ACTIVE_TAP)
	  if (tap->fd != current_fd)
	    {
	      write (tap->fd, packet + 1, packet_len - 1);
	      debug3 ("tap_fd %d: write packet", tap->fd);

	    }
    }
  dump (packet, packet_len);
}

inline void
forward_to_peer (char *packet, u_int packet_len, int current_fd, int max_fd)
{

  int fd;
  peer_handler_t *peer;

  packet[0] = DATA_PACKET;
  for (fd = 3; fd <= max_fd; fd++)
    {
      peer = get_fd_related_peer (fd);
      if (peer != NULL)
	if (peer->flags & ACTIVE_PEER)
	  if (peer->fd != current_fd)
	    {
	      xSSL_write (peer->ssl, packet, packet_len + 1,
			  "forwarding data");
	      debug3 ("sock_fd %d (0x%x ssl): write packet", peer->fd,
		      peer->ssl, packet_len);

	    }
    }

  dump (packet, packet_len);
}

int
verify_ssl_cert (SSL * ssl)
{
  char *fingerprint;
  char answer;

  if (SSL_get_verify_result (ssl) != X509_V_OK)
    {
      fingerprint = get_fingerprint_from_ctx (ssl);
      printf
	("\nCould not verify SSL servers certificate (self signed).\nFingerprint is: %s\nDo you want to continue? [y|n]: ",
	 fingerprint);
      fflush (stdout);
      scanf ("%c%*c", &answer);
      if (answer == 'y' || answer == 'Y')
	return TRUE;
      else
	return FALSE;
    }

  return TRUE;
}

void *
check_connections_queue (void *arg)
{

  int i;
  user_list_t *user_list;
  user_list = (user_list_t *) arg;

  if (user_list->count == 0)
    return NULL;

  for (i = 0; i < user_list->count; i++)

    /* check if we're connected to peer */
    if (!user_is_connected (user_list->user[i]))
      peer_connect (user_list->address[i], PORT);

  return NULL;
}
