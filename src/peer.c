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

peer_handler_t peer_db[MAX_PEERS];
pthread_mutex_t peer_db_mutex;

int peer_count;
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
register_peer (int fd, SSL * ssl, char *user, int address, net_ls_t * nl)
{

  peer_db[peer_count].fd = fd;
  peer_db[peer_count].ssl = ssl;
  peer_db[peer_count].state = ACTIVE;

  peer_db[peer_count].address = address;
  peer_db[peer_count].user = user;

  peer_db[peer_count].nl = nl;

  peer_count++;
  set_max_peer_fd ();

  FD_SET (fd, &master);
  debug2 ("Added fd %d to fd_set master (1st free fd: %d)", fd, peer_count);

  if (select_t != (pthread_t) NULL)
    {
      if (pthread_cancel (select_t))
	fatal ("Cannot cancel select thread");
      else
	pthread_create (&select_t, NULL, select_loop, NULL);
    }

  return peer_db + peer_count - 1;
}

void
deregister_peer (int fd)
{

  int i;
  int j;
  int k;

  for (i = 0; i < max_peer_fd; i++)
    if (peer_db[i].fd == fd)
      {
	SSL_free (peer_db[i].ssl);
	free (peer_db[i].user);
	free (peer_db[i].nl);
	memset (&peer_db[i], '\x00', sizeof (peer_handler_t));

	FD_CLR (fd, &master);
	close (fd);

	/* rebuild peer_db */
	/* XXX: test it (rewrite using lists) */
	for (j = 0; j < peer_count - 1; i++)
	  if (peer_db[j].fd == 0)
	    for (k = j; k < peer_count - 2; k++)
	      peer_db[k] = peer_db[k + 1];

	peer_count--;
	set_max_peer_fd ();

	debug2 ("Removed fd %d from fd_set master (current fd %d)", fd, peer_count);

	return;
      }
}

void *
free_non_active_peer (void *arg __attribute__ ((unused)))
{
  int i;

  /* wait until select_loop ends its cycle */
  pthread_mutex_lock (&peer_db_mutex);

  debug2 ("freeing non active fd");
  for (i = 0; i < peer_count; i++)
    if (peer_db[i].fd != 0)
      if (peer_db[i].state == CLOSING)
	{
	  set_routing (peer_db + i, DEL_ROUTING);
	  deregister_peer (peer_db[i].fd);
	}

  /* restart select thread and unlock mutex */
  pthread_cancel (select_t);
  pthread_mutex_unlock (&peer_db_mutex);
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
  for (i = 0; i < max_peer_fd; i++)
    if (peer_db[i].state == ACTIVE)
      if (!strcmp (peer_db[i].user, user))
	return TRUE;

  return FALSE;
}
