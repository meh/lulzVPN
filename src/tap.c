/*
 * "tap.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

#include <lulznet/config.h>
#include <lulznet/log.h>
#include <lulznet/networking.h>
#include <lulznet/peer.h>
#include <lulznet/tap.h>
#include <lulznet/xfunc.h>

tap_handler_t tap_db[MAX_TAPS];
int tap_count;
int max_tap_fd;

void
set_max_tap_fd ()
{

  int i;
  int max_tap_fd = 0;
  for (i = 0; i < tap_count; i++)
    if (tap_db[i].fd > max_tap_fd)
      max_tap_fd = tap_db[i].fd;
}

int
tap_alloc (char *dev)
{

  /* TODO: add *bsd support */
  struct ifreq ifr;
  int fd, err;

  if ((fd = open ("/dev/net/tun", O_RDWR)) < 0)
    fatal ("Could not open /dev/net/tun device");

  memset (&ifr, 0, sizeof (ifr));

  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  strncpy (ifr.ifr_name, "lulz%d", IFNAMSIZ);

  if ((err = ioctl (fd, TUNSETIFF, (void *) &ifr)) < 0)
    {
      close (fd);
      fatal ("Could not allocate tap device");
    }

  strcpy (dev, ifr.ifr_name);
  debug1 ("%s device create (fd %d).", dev, fd);
  return fd;
}

void
register_tap_device (int fd, char *device, int address, int netmask)
{

  int net_class;

  net_class = 0;

  pthread_mutex_lock (&peer_db_mutex);

  tap_db[tap_count].fd = fd;
  tap_db[tap_count].flags |= PEER_ACTIVE_TAP;
  tap_db[tap_count].device = device;
  tap_db[tap_count].address = address;
  tap_db[tap_count].netmask = netmask;
  tap_db[tap_count].network = get_ip_address_network (address, netmask);

  tap_count++;
  set_max_tap_fd ();

  FD_SET (fd, &master);
  debug2 ("Added fd %d to fd_set master (1st free fd: %d)", fd, tap_count);

  if (select_t != (pthread_t) NULL)
    {
      if (pthread_cancel (select_t))
	fatal ("Cannot cancel select thread");
      else
	pthread_create (&select_t, NULL, select_loop, NULL);
    }

  pthread_mutex_unlock (&peer_db_mutex);
}


void
deregister_tap (int fd)
{
  int i;
  int j;
  int k;

  for (i = 0; i < tap_count; i++)
    if (tap_db[i].fd == fd)
      {
	free (tap_db[i].device);
	memset (&tap_db[i], '\x00', sizeof (tap_handler_t));

	FD_CLR (fd, &master);
	close (fd);

	/* rebuild tap_db */
	for (j = 0; j < tap_count - 1; i++)
	  if (tap_db[j].fd == 0)
	    for (k = j; k < tap_count - 2; k++)
	      tap_db[k] = tap_db[k + 1];

	tap_count--;
	set_max_tap_fd ();

	debug2 ("Removed fd %d from fd_set master (current fd %d)", fd, tap_count);
	return;
      }
}

void *
free_non_active_tap ()
{

  int i;

  /* wait until select_loop ends its cycle */
  pthread_mutex_lock (&peer_db_mutex);

  for (i = 0; i < MAX_TAPS; i++)
    if (tap_db[i].fd != 0)
      if ((!(tap_db[i].flags & PEER_ACTIVE_TAP)))

	deregister_tap (tap_db[i].fd);

  /* restart select thread and unlock mutex */
  pthread_cancel (select_t);
  pthread_mutex_unlock (&peer_db_mutex);
  pthread_create (&select_t, NULL, select_loop, NULL);

  return NULL;
}

int
configure_tap_device (char *device, char *address, char *netmask)
{
  char ifconfig_command[256];

  sprintf (ifconfig_command, "/sbin/ifconfig %s %s netmask %s", device, address, netmask);
  system (ifconfig_command);

  return 1;

}

void
set_routing (peer_handler_t * peer, char op)
{
  char route_command[256];

  char gateway[ADDRESS_LEN];
  char network[ADDRESS_LEN];
  char netmask[ADDRESS_LEN];

  net_ls_t *local_nl;
  net_ls_t *remote_nl;

  int i;
  int j;

  local_nl = get_user_allowed_networks (peer->user);
  remote_nl = peer->nl;


  for (i = 0; i < local_nl->count; i++)
    {

      inet_ntop (AF_INET, &local_nl->address[i], gateway, ADDRESS_LEN);

      for (j = 0; j < remote_nl->count; j++)
	{
	  inet_ntop (AF_INET, &remote_nl->network[j], network, ADDRESS_LEN);
	  inet_ntop (AF_INET, &remote_nl->netmask[j], netmask, ADDRESS_LEN);

	  if (op == ADD_ROUTING)
	    sprintf (route_command, "/sbin/route add -net %s netmask %s gw %s", network, netmask, gateway);
	  else
	    sprintf (route_command, "/sbin/route del -net %s netmask %s gw %s", network, netmask, gateway);

	  system (route_command);
	}
    }

}

char *
get_ip_address_default_netmask (char *address)
{

  int first_ottect;
  char *netmask = (char *) malloc (ADDRESS_LEN * sizeof (char));

  sscanf (address, "%d.", &first_ottect);

  /* XXX: it's only a draft */
  if (first_ottect < 128)
    sprintf (netmask, "255.0.0.0");
  else if (first_ottect < 192)
    sprintf (netmask, "255.255.0.0");
  else
    sprintf (netmask, "255.255.255.0");

  return netmask;
}

int
get_ip_address_network (int address, int netmask)
{

  char p_address[ADDRESS_LEN];
  char p_network[ADDRESS_LEN];
  int o1, o2, o3;
  int net;

  /* XXX: it's only a draft */
  netmask = 0;
  inet_ntop (AF_INET, &address, p_address, ADDRESS_LEN);

  sscanf (p_address, "%d.%d.%d", &o1, &o2, &o3);
  sprintf (p_network, "%d.%d.%d.0", o1, o2, o3);

  net = xinet_pton (p_network);

  return net;
}

net_ls_t *
get_user_allowed_networks (char *user __attribute__ ((unused)))
{

  int i;
  net_ls_t *nl;

  nl = (net_ls_t *) xmalloc (sizeof (net_ls_t));
  nl->count = 0;

  for (i = 0; i < tap_count; i++)
    {
      /* TODO:add acl check 
         for now all users are allowed to connect to all network
         for (j = 0; tap_db[i].allowed_users[j] != NULL; j++)
         {
         if (!strcmp (tap_db[i].allowed_users[j], user))
         { 
       */
      nl->device[nl->count] = tap_db[i].device;
      nl->address[nl->count] = tap_db[i].address;
      nl->network[nl->count] = tap_db[i].network;
      nl->netmask[nl->count] = tap_db[i].netmask;
      nl->count++;
    }

  return nl;
}

int
new_tap (char *address, char *netmask)
{

  int fd;
  char *device = (char *) xmalloc (IFNAMSIZ * sizeof (char));
  int n_address;
  int n_netmask;

  if (netmask == NULL)
    netmask = get_ip_address_default_netmask (address);

  fd = tap_alloc (device);
  configure_tap_device (device, address, netmask);

  n_address = xinet_pton (address);
  n_netmask = xinet_pton (netmask);

  register_tap_device (fd, device, n_address, n_netmask);

  return 1;
}
