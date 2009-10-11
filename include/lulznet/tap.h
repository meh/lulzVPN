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

#define ACTIVE_TAP	0x00000001

#define CLASS_A		1
#define CLASS_B		2
#define CLASS_C		3

/* A structure that keep file descriptors information */
tap_handler_t tap_db[MAX_TAPS];

/* Allocate a new tap device */
int tap_alloc (char *dev);

/* search first free position in tap_db */
int get_first_free_tap_fd ();

int get_max_tap_fd ();

/* Register a new fd in the tap_db structure */
void register_tap_device (int fd, char *device, int address, int netmask);

/* Remove tap device data from tap_db*/
void deregister_tap (int fd);

void *free_non_active_tap ();

tap_handler_t *get_fd_related_tap (int fd);

/* Set address of tap device */
int configure_tap_device (char *device, char *address, char *netmask);

int add_user_routing (char *username, network_list_t * remote_nl);

char *get_ip_address_default_netmask (char *address);

int get_ip_address_network (int address, int netmask);

network_list_t *get_user_allowed_networks (char *user __attribute__ ((unused)));

int new_tap (char *address, char *netmask);
