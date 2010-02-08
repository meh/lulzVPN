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

const char addRouting = 0x01;
const char delRouting = 0x02;

const int CLASS_A = 1;
const int CLASS_B = 2;
const int CLASS_C   = 3;

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
char _id;
std::string _device;
std::string _networkName;

int _address;
int _netmask;
int _network;

int alloc (std::string NetName, std::string *dev);

public:
Tap (TapDeviceT TapOpt);
~Tap ();
bool operator>> (Packet::Packet * packet);
bool operator<< (Packet::Packet * packet);
bool isActive ();
bool isRoutableAddress(int address);
bool isReadyToRead(fd_set *rdSel);
void showInfo();

public:
int fd ();
uChar id ();
std::string device ();
std::string networkName ();
int address ();
int netmask ();
};

/* A structure that keep file descriptors information */
extern std::vector<Tap *>db;
extern pthread_mutex_t db_mutex;

extern int maxFd;

void Register(Tap *t);

/* set global var max_tap_fd to proper value */
void SetMaxFd ();

void FreeNonActive ();

Tap *get_fd_related (int fd);

/* Set address of tap device */
int configureDevice (std::string device, std::string address, std::string netmask);

void setSystemRouting (Peers::Peer * peer, std::vector<networkT> allowedNets, char op);

int getDefaultNetmask (int address);

int getCidrNotation(int netmask);

#define get_ip_address_network(address, netmask) ((address) & (netmask))

std::vector<networkT> getUserAllowedNetworks (std::string user);

uChar getNetworkId(std::string networkName);
}
#endif
