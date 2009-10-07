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

#include "headers/lulznet.h"

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

int
get_first_free_tap_db_position ()
{
  int i;
  for (i = 0; i < MAX_TAPS; i++)
    if (tap_db[i].fd == 0)
      break;

  return i;
}

int
get_max_tap_fd ()
{

  int i;
  int max = 0;
  for (i = 0; i < MAX_TAPS; i++)
    if (tap_db[i].fd > max)
      max = tap_db[i].fd;

  return max;
}

void
register_tap_device (int fd, char *device, int address, int netmask)
{

  int first_free_fd = get_first_free_tap_db_position ();
  int class;

  class = 0;

  pthread_mutex_lock (&select_mutex);

  tap_db[first_free_fd].fd = fd;
  tap_db[first_free_fd].flags |= ACTIVE_TAP;
  tap_db[first_free_fd].device = device;
  tap_db[first_free_fd].address = address;
  tap_db[first_free_fd].netmask = netmask;
  tap_db[first_free_fd].network = get_ip_address_network (address, netmask);

  FD_SET (fd, &master);
  debug2 ("Added fd %d to fd_set master (1st free fd: %d)", fd, first_free_fd);

  if (select_t != (pthread_t) NULL)
    {
      if (pthread_cancel (select_t))
	fatal ("Cannot cancel select thread");
      else
	pthread_create (&select_t, NULL, select_loop, NULL);
    }

  pthread_mutex_unlock (&select_mutex);
}


void
deregister_tap (int fd)
{
  int i;

  for (i = 0; i < MAX_TAPS; i++)
    {
      if (tap_db[i].fd == fd)
	{
	  free (tap_db[i].device);
	  memset (&tap_db[i], '\x00', sizeof (tap_handler_t));

	  FD_CLR (fd, &master);
	  close (fd);

	  debug2 ("Removed fd %d from fd_set master (current fd %d)", fd, get_first_free_tap_db_position ());
	  return;
	}
    }
}

void *
free_non_active_tap ()
{

  int i;

  /* wait until select_loop ends its cycle */
  pthread_mutex_lock (&select_mutex);

  for (i = 0; i < MAX_TAPS; i++)
    if (tap_db[i].fd != 0)
      if ((!(tap_db[i].flags & ACTIVE_TAP)))

	deregister_tap (tap_db[i].fd);

  /* restart select thread and unlock mutex */
  pthread_cancel (select_t);
  pthread_mutex_unlock (&select_mutex);
  pthread_create (&select_t, NULL, select_loop, NULL);

  return NULL;
}

tap_handler_t *
get_fd_related_tap (int fd)
{
  int i;
  for (i = 0; i < MAX_TAPS; i++)
    if (tap_db[i].fd == fd)
      return (tap_db + i);

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

int
add_user_routing (char *username, network_list_t * remote_nl)
{
  char route_command[256];

  char gateway[ADDRESS_LEN];
  char network[ADDRESS_LEN];
  char netmask[ADDRESS_LEN];

  network_list_t *nl;

  int i;
  int j;

  nl = get_user_allowed_networks (username);	/* TODO: avoid to call function two times */

  for (i = 0; i < nl->count; i++)
    {

      inet_ntop (AF_INET, &nl->address[i], gateway, ADDRESS_LEN);
      for (j = 0; j < remote_nl->count; j++)
	{
	  inet_ntop (AF_INET, &remote_nl->network[i], network, ADDRESS_LEN);
	  inet_ntop (AF_INET, &remote_nl->netmask[i], netmask, ADDRESS_LEN);

	  sprintf (route_command, "/sbin/route add -net %s netmask %s gw %s", network, netmask, gateway);
	  system (route_command);
	}
    }


  return 1;
}

char *
get_ip_address_default_netmask (char *address)
{

  int first_ottect;
  char *netmask = malloc (ADDRESS_LEN * sizeof (char));

  sscanf (address, "%d.", &first_ottect);

  /* TODO: it's only a draft */
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

  netmask = 0;
  inet_ntop (AF_INET, &address, p_address, ADDRESS_LEN);

  sscanf (p_address, "%d.%d.%d", &o1, &o2, &o3);
  sprintf (p_network, "%d.%d.%d.0", o1, o2, o3);

  net = xinet_pton (p_network);

  return net;
}

network_list_t *
get_user_allowed_networks (char *user __attribute__ ((unused)))
{

  int max_fd;
  int i;
  network_list_t *nl;

  max_fd = get_max_fd ();
  nl = malloc (sizeof (network_list_t));
  nl->count = 0;

  for (i = 0; i < MAX_TAPS; i++)
    {
      if (tap_db[i].flags & ACTIVE_TAP)
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
    }

  return nl;
}

int
new_tap (char *address, char *netmask)
{

  int fd;
  char *device = xmalloc (IFNAMSIZ * sizeof (char));
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
