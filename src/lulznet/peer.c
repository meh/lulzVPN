/*
 * "peer.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

#include <lulznet/config.h>
#include <lulznet/log.h>
#include <lulznet/networking.h>
#include <lulznet/peer.h>
#include <lulznet/tap.h>
#include <lulznet/xfunc.h>

int
get_first_free_peer_db_position ()
{
  int i;
  for (i = 0; i < MAX_PEERS; i++)
    if (peer_db[i].fd == 0)
      break;

  return i;
}

int
get_max_peer_fd ()
{

  int i;
  int max = 0;
  for (i = 0; i < MAX_PEERS; i++)
    if (peer_db[i].fd > max)
      max = peer_db[i].fd;

  return max;
}

void
register_peer (int fd, SSL * ssl, char *user, int address,
	       network_list_t * nl, char flags)
{

  int first_free_fd = get_first_free_peer_db_position ();

  pthread_mutex_lock (&select_mutex);

  peer_db[first_free_fd].fd = fd;
  peer_db[first_free_fd].ssl = ssl;
  peer_db[first_free_fd].flags = flags | ACTIVE_PEER;

  peer_db[first_free_fd].address = address;
  peer_db[first_free_fd].user = user;

  peer_db[first_free_fd].nl = nl;

  FD_SET (fd, &master);
  debug2 ("Added fd %d to fd_set master (1st free fd: %d)", fd,
	  first_free_fd);

  if (select_t != (pthread_t) NULL)
    {
      if (pthread_cancel (select_t))
	fatal ("Cannot cancel select thread");
      else
	pthread_create (&select_t, NULL, select_loop, NULL);
    }

  pthread_mutex_unlock (&select_mutex);
}

int
is_active_peer_fd (int fd)
{
  int i;
  for (i = 0; i < MAX_PEERS; i++)
    {
      if (peer_db[i].fd == fd)
	if (peer_db[i].flags & ACTIVE_PEER)
	  {
	    debug3 ("fd %d type sock is active", fd);
	    return TRUE;
	  }
    }

  return FALSE;
}

void
set_non_active_peer (int fd)
{

  int i;
  for (i = 0; i < MAX_PEERS; i++)
    if (peer_db[i].fd == fd)
      peer_db[i].flags ^= ACTIVE_PEER;
}

void
deregister_peer (int fd)
{

  int i;

  for (i = 0; i < MAX_PEERS; i++)
    {
      if (peer_db[i].fd == fd)
	{
	  SSL_free (peer_db[i].ssl);
	  free (peer_db[i].user);
	  free (peer_db[i].nl);
	  memset (&peer_db[i], '\x00', sizeof (peer_handler_t));

	  FD_CLR (fd, &master);
	  close (fd);

	  debug2 ("Removed fd %d from fd_set master (current fd %d)", fd,
		  get_first_free_peer_db_position ());
	  return;
	}
    }
}

void *
free_non_active_peer ()
{
  int i;

  /* wait until select_loop ends its cycle */
  pthread_mutex_lock (&select_mutex);

  debug2 ("freeing non active fd");
  for (i = 0; i < MAX_PEERS; i++)
    if (peer_db[i].fd != 0)
      if ((!(peer_db[i].flags & ACTIVE_PEER)))
	deregister_peer (peer_db[i].fd);


  /* restart select thread and unlock mutex */
  pthread_cancel (select_t);
  pthread_mutex_unlock (&select_mutex);
  pthread_create (&select_t, NULL, select_loop, NULL);

  return NULL;
}

peer_handler_t *
get_fd_related_peer (int fd)
{

  int i;

  for (i = 0; i < MAX_PEERS; i++)
    if (peer_db[i].fd == fd)
      return (peer_db + i);

  return NULL;
}

int
user_is_connected (char *user)
{
  int i;
  for (i = 0; i < MAX_PEERS; i++)
    if (peer_db[i].flags & ACTIVE_PEER)
      if (!strcmp (peer_db[i].user, user))
	return TRUE;

  return FALSE;
}
