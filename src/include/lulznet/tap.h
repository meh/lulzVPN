/*
 * "tap.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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
#ifndef _LNET_TAP_H
#define _LNET_TAP_H

#define PEER_ACTIVE_TAP	0x00000001

#define ADD_ROUTING 	0x01
#define DEL_ROUTING	0x02

#define CLASS_A		1
#define CLASS_B		2
#define CLASS_C		3

typedef struct
{
  int fd;
  char flags;
  char *device;
  int address;
  int netmask;
  int network;

  char *allowed_users[MAX_PEERS];
  int allowed_users_count;

} tap_handler_t;

/* A structure that keep file descriptors information */
extern tap_handler_t tap_db[MAX_TAPS];
extern int tap_count;
extern int max_tap_fd;

/* Allocate a new tap device */
int tap_alloc (char *dev);

/* set global var max_tap_fd to proper value */
void set_max_tap_fd ();

/* Register a new fd in the tap_db structure */
void register_tap_device (int fd, char *device, int address, int netmask);

/* Remove tap device data from tap_db*/
void deregister_tap (int fd);

void *free_non_active_tap ();

tap_handler_t *get_fd_related_tap (int fd);

/* Set address of tap device */
int configure_tap_device (char *device, char *address, char *netmask);

void set_routing (peer_handler_t *peer, char op);

int get_ip_address_default_netmask (int address);

#define get_ip_address_network(address, netmask) ((address) & (netmask))

net_ls_t *get_user_allowed_networks (char *user);

int new_tap (char *address, char *netmask);

#endif
