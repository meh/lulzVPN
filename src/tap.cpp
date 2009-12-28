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
#include <lulznet/protocol.h>
#include <lulznet/tap.h>
#include <lulznet/xfunc.h>

std::vector < Taps::Tap * >Taps::db;
pthread_mutex_t Taps::db_mutex;

int Taps::maxFd;

void
Taps::SetMaxFd ()
{

  uInt i;
  maxFd = 0;

  for (i = 0; i < db.size(); i++)
    if (db[i]->fd() > maxFd)
      maxFd = db[i]->fd();
}

int
Taps::Tap::alloc (std::string NetName, std::string * dev)
{

  /* TODO: add *bsd support */
  struct ifreq ifr;
  int fd, err;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    Log::Fatal("Could not open /dev/net/tun device");

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  snprintf(ifr.ifr_name, IFNAMSIZ, "%s%%d", (char *) NetName.c_str());

  if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
    close(fd);
    Log::Fatal("Could not allocate tap device");
  }

  dev->assign(ifr.ifr_name);

  Log::Debug1("%s device create (fd %d).", dev->c_str(), fd);
  return fd;
}

Taps::Tap::Tap(TapDeviceT TapOpt)
{

  int n_address;
  int n_netmask;
  std::string device;

  n_address = xinet_pton((char *) TapOpt.Address.c_str());

  if (TapOpt.Netmask.empty()) {
    n_netmask = htonl(getDefaultNetmask(n_address));
    inet_ntop(AF_INET, &n_netmask, (char *) TapOpt.Netmask.c_str(), ADDRESS_LEN);
  }
  else
    n_netmask = xinet_pton((char *) TapOpt.Netmask.c_str());

  _fd = alloc(TapOpt.networkName, &device);
  _state = TAP_ACTIVE;
  _device = device;
  _networkName = TapOpt.networkName;
  _address = n_address;
  _netmask = n_netmask;
  _network = get_ip_address_network(n_address, n_netmask);

  configureDevice(device, TapOpt.Address, TapOpt.Netmask);

  db.push_back(this);

  SetMaxFd();

  FD_SET(_fd, &Network::master);

  Log::Debug2("Added fd %d to fd_set master (1st free fd: %d)", _fd, db.size());

  Network::Server::RestartSelectLoop();
}


Taps::Tap::~Tap()
{

  FD_CLR(_fd, &Network::master);
  close(_fd);


  Log::Debug2("Removed fd %d from fd_set master (current fd %d)", _fd, db.size());
}

bool
Taps::Tap::operator>> (Network::Packet * packet)
{
  if (!(packet->length = read(_fd, packet->buffer + 2, 4094))) {
    _state = TAP_CLOSING;
    return FAIL;
  }


  Log::Debug3("Read %d bytes packet from tap %s", packet->length, _device.c_str());
  return DONE;
}

bool
Taps::Tap::operator<< (Network::Packet * packet)
{
  if (!write(_fd, packet->buffer + 2, packet->length - 2)) {
    _state = TAP_CLOSING;
    return FAIL;
  }


  Log::Debug3("\tForwarded to tap %s", _device.c_str());
  return DONE;
}

bool
Taps::Tap::isRoutableAddress (int address)
{
  if (_network == get_ip_address_network(address, _netmask))
    return true;

  return false;
}

bool
Taps::Tap::isActive ()
{
  if (_state == TAP_ACTIVE)
    return true;

  return false;
}

bool
Taps::Tap::isReadyToRead (fd_set * rdSel)
{
  if (FD_ISSET(_fd, rdSel))
    return true;

  return false;
}

void
Taps::Tap::showInfo ()
{

}

int
Taps::Tap::fd ()
{
  return _fd;
}

int
Taps::Tap::address ()
{
  return _address;

}

int
Taps::Tap::netmask ()
{
  return _netmask;

}

std::string
Taps::Tap::device ()
{
  return _device;

}

std::string
Taps::Tap::networkName ()
{
  return _networkName;

}

void
Taps::FreeNonActive ()
{

  uInt i;
  std::vector < Taps::Tap * >::iterator it;

  for (i = 0; i < db.size(); i++)
    if (!db[i]->isActive()) {
      delete db[i];
      db[i] = NULL;

      it = db.begin();
      it += i;
      db.erase(it);
      SetMaxFd();
    }
}

int
Taps::getDefaultNetmask (int address)
{
  uChar *cAddr;
  int netmask;

  cAddr = (uChar *) &address;

  if (cAddr[0] < (uChar) 128)
    netmask = 0xff000000;
  else if (cAddr[0] < (uChar) 192)
    netmask = 0xffff0000;
  else
    netmask = 0xffffff00;

  return netmask;
}

int
Taps::getCidrNotation (int netmask)
{

  int cidrNetmask = 32;

  while (!(netmask & 1) && cidrNetmask > 0) {
    netmask >>= 1;
    cidrNetmask--;
  }

  return cidrNetmask;
}

int
Taps::configureDevice (std::string device, std::string address, std::string netmask)
{
  char ifconfig_command[256];

  sprintf(ifconfig_command, "ifconfig %s %s netmask %s", device.c_str(), address.c_str(), netmask.c_str());
  system(ifconfig_command);


  Log::Debug2("Ifconfig command: %s", ifconfig_command);

  return 1;
}

networkT
Taps::getUserAllowedNetworks (std::string user)
{
  uInt i;
  uInt j;
  uInt k;
  networkT nl;

  /* Get current user config */
  for (i = 0; i < Options.UserCredentialsCount(); i++)
    if (!Options.UserCredentials(i).Name.compare(user))
      break;

  /* For each network check if it is allowed in the AllowedNetworks list */
  for (j = 0; j < db.size(); j++)
    for (k = 0; k < Options.UserCredentials(i).AllowedNetworks.size(); k++)
      if (!Options.UserCredentials(i).AllowedNetworks[k].compare(db[j]->networkName())) {
        nl.networkName.push_back(db[j]->networkName());
        nl.remoteId.push_back((uChar) j);
        nl.address.push_back(db[j]->address());
        nl.netmask.push_back(db[j]->netmask());
        break;
      }

  return nl;
}

void
Taps::setSystemRouting (Peers::Peer * peer, networkT allowedNets, char op)
{
  char route_command[256];

  char gateway[ADDRESS_LEN + 1];
  char network[ADDRESS_LEN + 1];
  char netmask[ADDRESS_LEN + 1];

  networkT remoteNets;

  int i;
  int j;
  int allowedNetsCount;
  int remoteNetsCount;

  remoteNets = peer->nl();

  allowedNetsCount = allowedNets.networkName.size();
  remoteNetsCount = remoteNets.networkName.size();

  for (i = 0; i < allowedNetsCount; i++) {

    inet_ntop(AF_INET, &allowedNets.address[i], gateway, ADDRESS_LEN);

    for (j = 0; j < remoteNetsCount; j++)
      if (!allowedNets.networkName[i].compare(remoteNets.networkName[j])) {
        inet_ntop(AF_INET, &remoteNets.network[j], network, ADDRESS_LEN);
        inet_ntop(AF_INET, &remoteNets.netmask[j], netmask, ADDRESS_LEN);

        if (op == ADD_ROUTING)
          sprintf(route_command, "route add -net %s netmask %s gw %s", network, netmask, gateway);
        else
          sprintf(route_command, "route del -net %s netmask %s gw %s", network, netmask, gateway);


        Log::Debug2("Route command: %s", route_command);
        system(route_command);
      }
  }
}

uChar
Taps::getNetworkId (std::string networkName)
{
  char i;
  for (i = 0; i < (char) Taps::db.size(); i++)
    if (!Taps::db[i]->networkName().compare(networkName))
      break;

  return i;
}
