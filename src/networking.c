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
#include <lulznet/packet.h>
#include <lulznet/peer.h>
#include <lulznet/protocol.h>
#include <lulznet/tap.h>
#include <lulznet/xfunc.h>

SSL_CTX *ssl_client_ctx;
SSL_CTX *ssl_server_ctx;

fd_set master;
pthread_t select_t;

void
ssl_server_init ()
{
  ssl_server_ctx = SSL_CTX_new (SSLv23_server_method ());

  if (!ssl_server_ctx)
    fatal ("Failed to do SSL CTX new");

  debug2 ("Loading SSL certificate");
  if (SSL_CTX_use_certificate_file (ssl_server_ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0)
    fatal ("Failed to load SSL certificate %s", CERT_FILE);

  debug2 ("Loading SSL private key");
  if (SSL_CTX_use_PrivateKey_file (ssl_server_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
    fatal ("Failed to load SSL private key %s", KEY_FILE);
}

void
ssl_client_init ()
{
  ssl_client_ctx = SSL_CTX_new (SSLv23_client_method ());
}

void *
server_loop (void *arg __attribute__ ((unused)))
{

  int listen_sock, peer_sock;
  int on = 1;
  SSL *peer_ssl;
  char peer_address[ADDRESS_LEN];
  char request[1];
  struct sockaddr_in server;
  struct sockaddr_in peer;
  socklen_t addr_size;
  pthread_t connect_queue_t;
  hs_opt_t *hs_opt;
  peer_handler_t *new_peer;

  if ((listen_sock = socket (PF_INET, SOCK_STREAM, 0)) == -1)
    fatal ("cannot create socket");

  debug1 ("listen_sock (fd %d) created", listen_sock);
  if (setsockopt (listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) == -1)
    error ("setsockopt SO_REUSEADDR: %s", strerror (errno));

  server.sin_family = AF_INET;
  server.sin_port = htons (opt.binding_port);
  server.sin_addr.s_addr = INADDR_ANY;	/*(server_opt->binding_address); */
  memset (&(server.sin_zero), '\0', 8);

  debug1 ("Binding port %d", PORT);
  if (bind (listen_sock, (struct sockaddr *) &server, sizeof (struct sockaddr)) == -1)
    fatal ("cannot binding to socket");

  info ("Listening");
  if (listen (listen_sock, MAX_PEERS) == -1)
    fatal ("cannot listen");

  addr_size = sizeof (struct sockaddr_in);

  /* @TODO while(available_connection()) else sleep && goto! */
  while (1)
    {
      if ((peer_sock = accept (listen_sock, (struct sockaddr *) &peer, &addr_size)) == -1)
	fatal ("cannot accept");

      send_banner (peer_sock);

      if ((peer_ssl = SSL_new (ssl_server_ctx)) != NULL)
	{
	  SSL_set_fd (peer_ssl, peer_sock);

	  debug2 ("SSL Handshake");
	  if (SSL_accept (peer_ssl) > 0)
	    {

	      /* recv request type */
	      xSSL_read (peer_ssl, request, sizeof (char), "request type");

	      if (request[0] == NEW_PEER)
		{
		  if ((hs_opt = server_handshake (peer_ssl)))
		    {

		      pthread_mutex_lock (&peer_db_mutex);

		      new_peer = register_peer (peer_sock, peer_ssl, hs_opt->peer_username, peer.sin_addr.s_addr, hs_opt->net_ls);
		      inet_ntop (AF_INET, &peer.sin_addr.s_addr, peer_address, ADDRESS_LEN);
		      info ("Connection accepted from %s (fd %d)", peer_address, peer_sock);

		      /* Set routing */
		      set_routing (new_peer, ADD_ROUTING);

		      pthread_mutex_unlock (&peer_db_mutex);

		      pthread_create (&connect_queue_t, NULL, check_connections_queue, hs_opt->user_ls);
		      pthread_join (connect_queue_t, NULL);
		    }
		  else
		    {
		      error ("Cannot comlpete lulznet handshake");
		      SSL_free (peer_ssl);
		      close (peer_sock);
		    }
		}
	      else if (request[0] == AUTH_SERVICE)
		{
		  info ("Recv auth request");
		  auth_service (peer_ssl);
		}
	      else
		{
		  error ("Invalid request");
		  SSL_free (peer_ssl);
		  close (peer_sock);
		}
	    }
	  else
	    {
	      error ("Cannot complete SSL handshake");
	      close (peer_sock);
	    }
	}
    }
  free (hs_opt);
}

int
lookup_address (char *address)
{

  struct hostent *host_info;

  debug2 ("Looking up client %s", address);
  host_info = gethostbyname (address);

  if (host_info == NULL)
    {
      error ("Cannot lookup hostname", 1);
      return 0;
    }

  return *((int *) host_info->h_addr);

}

void
peer_connect (int address, short port)
{

  struct sockaddr_in peer;
  int peer_sock;
  SSL *peer_ssl;
  char request[1];
  hs_opt_t *hs_opt;
  pthread_t connect_queue_t;
  peer_handler_t *new_peer;

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
      {
	request[0] = NEW_PEER;
	xSSL_write (peer_ssl, request, 1, "new peer request");
	if ((hs_opt = peer_handshake (peer_ssl)))
	  {
	    pthread_mutex_lock (&peer_db_mutex);

	    new_peer = register_peer (peer_sock, peer_ssl, hs_opt->peer_username, address, hs_opt->net_ls);

	    free (hs_opt);
	    info ("Connected");

	    set_routing (new_peer, ADD_ROUTING);

	    pthread_mutex_unlock (&peer_db_mutex);

	    pthread_create (&connect_queue_t, NULL, check_connections_queue, hs_opt->user_ls);
	    pthread_join (connect_queue_t, NULL);

	  }
	else
	  {
	    error ("Cannot complete lulznet handshake");
	    SSL_free (peer_ssl);
	    close (peer_sock);
	  }
      }
    else
      {
	error ("Cannot verify host identity");
	SSL_free (peer_ssl);
	close (peer_sock);
      }
  else
    {
      error ("Cannot complete SSL handshake");
      SSL_free (peer_ssl);
      close (peer_sock);
    }
}

void
disassociation_request (int fd)
{

  char packet[3];
  peer_handler_t *peer;

  pthread_mutex_lock (&peer_db_mutex);

  peer = get_fd_related_peer (fd);

  sprintf ((char *) packet, "%c%c", CONTROL_PACKET, CLOSE_CONNECTION);
  xSSL_write (peer->ssl, packet, 2, "disconnection packet");

  set_routing (peer, DEL_ROUTING);
  deregister_peer (fd);

  pthread_mutex_unlock (&peer_db_mutex);
}

/* TODO: add cool routing */
void *
select_loop (void __attribute__ ((unused)) * arg)
{
  char packet_buffer[4096];
  int ret;
  fd_set read_select;
  int max_fd;
  int rd_len;
  int i;

  peer_handler_t *peer;
  tap_handler_t *tap;

  int dont_close_flag = 1;
  int free_fd_flag;

  while (dont_close_flag)
    {

      pthread_mutex_lock (&peer_db_mutex);

      read_select = master;
      free_fd_flag = 0;

      if (max_peer_fd > max_tap_fd)
	max_fd = max_peer_fd;
      else
	max_fd = max_tap_fd;

      pthread_mutex_unlock (&peer_db_mutex);

      ret = select (max_fd + 1, &read_select, NULL, NULL, NULL);

      pthread_mutex_lock (&peer_db_mutex);
      if (ret == -1)
	fatal ("Select error");
      else
	{
	  /* 0,1 and 2 are stdin-out-err and we don't care about them */
	  for (i = 0; i < peer_count; i++)
	    {
	      peer = peer_db + i;
	      if(peer->state == PEER_ACTIVE)
	      if (FD_ISSET (peer->fd, &read_select))
		{
		  /* Read from it */
		  debug3 ("sock_fd %d (0x%x ssl): read %d bytes packet", peer->fd, peer->ssl, rd_len);
		  rd_len = xSSL_read (peer->ssl, packet_buffer, 4095, "forwarding data");

		  if (rd_len == 0)
		    deregister_peer (peer->fd);
		  else
		    {

		      switch (packet_buffer[0])
			{
			case DATA_PACKET:
			  forward_to_tap (packet_buffer, rd_len);
			  break;
			case CONTROL_PACKET:
			  if (packet_buffer[1] == CLOSE_CONNECTION)
			    {
			      debug3 ("control_packet: closing connection");
			      free_fd_flag = 1;
			      peer->state = PEER_CLOSING;
			    }
			  else
			    error ("Unknow control flag");
			  break;
			}
		    }
		}
	    }

	  for (i = 0; i < tap_count; i++)
	    {
	      tap = tap_db + i;
	      if (FD_ISSET (tap->fd, &read_select))
		{
		  debug3 ("tap_fd %d: read %d bytes packet", tap->fd, rd_len);
		  rd_len = read (tap->fd, packet_buffer + 1, 4095);
		  forward_to_peer (packet_buffer, rd_len);
		}
	    }
	}

      if (free_fd_flag)
	  free_non_active_peer (NULL);

      /* When the cycle is end functions can modify the fd_db structure */
      pthread_mutex_unlock (&peer_db_mutex);

    }
  return NULL;
}

void
restart_select_loop(){

     debug2("Restarting select()");
  if (select_t != (pthread_t) NULL)
    {
      if (pthread_cancel (select_t))
	fatal ("Cannot cancel select thread");
      else
	pthread_create (&select_t, NULL, select_loop, NULL);
    }
}
inline void
forward_to_tap (char *packet, u_int packet_len)
{

  int i;
  tap_handler_t *tap;

  debug3 ("data_packet");
  for (i = 0; i < tap_count; i++)
    {
      tap = tap_db + i;
      debug3 ("tap_fd %d: write packet", tap->fd);
      write (tap->fd, packet + 1, packet_len - 1);
    }
  dump (packet, packet_len);
}

inline void
forward_to_peer (char *packet, u_int packet_len)
{

  int i;
  peer_handler_t *peer;

  packet[0] = DATA_PACKET;

  for (i = 0; i < peer_count; i++)
    {
      peer = peer_db + i;
      if (peer->state == PEER_ACTIVE)
	{
	  debug3 ("sock_fd %d (0x%x ssl): write packet", peer->fd, peer->ssl, packet_len);
	  if (!xSSL_write (peer->ssl, packet, packet_len + 1, "forwarding data"))
	    deregister_peer (peer->fd);
	}
    }

  get_destination_ip (packet + 1);
  dump (packet, packet_len);
}

int
verify_ssl_cert (SSL * ssl)
{
  char *fingerprint;

  if (SSL_get_verify_result (ssl) != X509_V_OK)
    {
      fingerprint = get_fingerprint_from_ctx (ssl);
      printf ("\nCould not verify SSL servers certificate (self signed).\nFingerprint is: %s\nDo you want to continue? [y|n]: ", fingerprint);
      fflush (stdout);

      /* FIXME: faggot scanf (doesn't work at the second time :| ) */
      /* for now we trust :O 
         scanf("%c%*c",&answer);

         if (answer == 'y' || answer == 'Y')
         return TRUE;
         else
         return FALSE; */
    }

  return TRUE;
}

void *
check_connections_queue (void *arg)
{

  int i;
  user_ls_t *user_ls;
  user_ls = (user_ls_t *) arg;

  if (user_ls->count == 0)
    return NULL;

  for (i = 0; i < user_ls->count; i++)

    /* check if we're connected to peer */
    if (!user_is_connected (user_ls->user[i]))
      peer_connect (user_ls->address[i], PORT);

  return NULL;
}
