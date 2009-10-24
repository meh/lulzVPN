/*
 * "peer.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
 *
 * lulzNet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * lulzNet is distributed in the hope that it will be useful,
 * but WITH ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
*/

#include <lulznet/lulznet.h>

#include <lulznet/config.h>
#include <lulznet/log.h>
#include <lulznet/networking.h>
#include <lulznet/peer.h>
#include <lulznet/tap.h>
#include <lulznet/xfunc.h>

peer_handler_t peer_db[MAX_PEERS];
pthread_mutex_t peer_db_mutex;

int peer_count;
int connections_to_peer;
int max_peer_fd;

void
set_max_peer_fd ()
{
  int i;
  max_peer_fd = 0;

  for (i = 0; i < peer_count; i++)
    if (peer_db[i].fd > max_peer_fd)
      max_peer_fd = peer_db[i].fd;
}

peer_handler_t *
register_peer (int fd, SSL * ssl, char *user, int address, net_ls_t * nl, char type)
{
  peer_db[peer_count].fd = fd;
  peer_db[peer_count].ssl = ssl;

  peer_db[peer_count].state = PEER_ACTIVE;
  peer_db[peer_count].type = type;

  if (type == OUTGOING_CONNECTION)
    connections_to_peer++;

  peer_db[peer_count].address = address;
  peer_db[peer_count].user = user;

  peer_db[peer_count].nl = nl;

  peer_count++;
  set_max_peer_fd ();

  FD_SET (fd, &master);
  debug2 ("Added fd %d to fd_set master (1st free fd: %d)", fd, peer_count);

  /* restart select thread so select() won't block world */
  restart_select_loop ();
  return peer_db + peer_count - 1;
}

void
deregister_peer (int fd)
{
  int i;

  for (i = 0; i < max_peer_fd; i++)
    if (peer_db[i].fd == fd)
      {
	SSL_free (peer_db[i].ssl);
	free (peer_db[i].user);
	free (peer_db[i].nl);
	peer_db[i].state = PEER_STOPPED;

	if (peer_db[i].type == OUTGOING_CONNECTION)
	  connections_to_peer--;

	FD_CLR (fd, &master);
	close (fd);

	debug2 ("Removed fd %d from fd_set master (current fd %d)", fd, peer_count);
	return;
      }
}

void
free_non_active_peer ()
{
  int i;

  debug2 ("freeing non active fd");
  for (i = 0; i < peer_count; i++)
    if (peer_db[i].state == PEER_CLOSING)
      {
	set_routing (peer_db + i, DEL_ROUTING);
	deregister_peer (peer_db[i].fd);
      }

  rebuild_peer_db ();
}

void
rebuild_peer_db ()
{
  int i;
  int j;
  int freed_peer;

  freed_peer = 0;
  j = 0;

  for (i = 0; i < peer_count; i++)
    if (peer_db[i].state != PEER_STOPPED)
      peer_db[j++] = peer_db[i];
    else
      freed_peer++;

  peer_count -= freed_peer;
  set_max_peer_fd ();
}

peer_handler_t *
get_fd_related_peer (int fd)
{
  int i;

  for (i = 0; i < MAX_PEERS; i++)
    if (peer_db[i].state == PEER_ACTIVE && peer_db[i].fd == fd)
      return (peer_db + i);

  return NULL;
}

int
user_is_connected (char *user)
{
  int i;

  for (i = 0; i < max_peer_fd; i++)
    if (peer_db[i].state == PEER_ACTIVE)
      if (!strcmp (peer_db[i].user, user))
	return TRUE;

  return FALSE;
}
