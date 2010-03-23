/*
 * "tap.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
 *
 * lulzVPN is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * lulzVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */

#ifndef LVPN_TAP_H
#define LVPN_TAP_H

#include "packet.h"

namespace Taps 
{
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
bool operator>> (Packet::DataPacket * packet);
bool operator<< (Packet::DataPacket * packet);
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
}
#endif
