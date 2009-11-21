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

#define TAP_ACTIVE	0x01
#define TAP_CLOSING	0x02

#define ADD_ROUTING 	0x01
#define DEL_ROUTING	0x02

#define CLASS_A		1
#define CLASS_B		2
#define CLASS_C		3

namespace Taps
{

/* Allocate a new tap device */
/* Register a new fd in the tap_db structure */
/* Remove tap device data from tap_db*/

class Tap
{
private:
  int _fd;
  char _state;
  std::string _device;
  int _address;
  int _netmask;
  int _network;

  int alloc (std::string *dev);

public:
  Tap (std::string address, std::string netmask);
  ~Tap ();
  bool operator>> (Network::Packet * packet);
  bool operator<< (Network::Packet * packet);
  bool isActive ();
  bool isReadyToRead(fd_set *rd_sel);
  void showInfo();

public:
  int fd ();
  std::string device ();
  int address ();
  int netmask ();
  int network ();
};

/* A structure that keep file descriptors information */
extern Tap *db[MAX_TAPS];
extern pthread_mutex_t db_mutex;
extern int count;
extern int max_fd;

/* set global var max_tap_fd to proper value */
void set_max_fd ();

void free_non_active ();

void rebuild_db ();

Tap *get_fd_related (int fd);

/* Set address of tap device */
int configure_device (std::string device, std::string address, std::string netmask);

void set_system_routing (Peers::Peer * peer, char op);

int get_ip_address_default_netmask (int address);

#define get_ip_address_network(address, netmask) ((address) & (netmask))

net_ls_t get_user_allowed_networks (std::string user);

}
#endif
