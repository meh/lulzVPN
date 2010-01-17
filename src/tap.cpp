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
Taps::Register(Tap *t){

  db.push_back(t);

  Log::Debug2("Added fd %d to fd_set master", t->fd());
  FD_SET(t->fd(), &Network::master);

  SetMaxFd();

  /* restart select thread so select() won't block world */
  Network::Server::RestartSelectLoop();
}

void
Taps::SetMaxFd ()
{
  std::vector<Tap *>::iterator tapIt, tapEnd;
  maxFd = 0;

  tapEnd = db.end();
  for (tapIt = db.begin(); tapIt < tapEnd; tapIt++)
    if ((*tapIt)->fd() > maxFd)
      maxFd = (*tapIt)->fd();
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
    inet_ntop(AF_INET, &n_netmask, (char *) TapOpt.Netmask.c_str(), addressLenght);
  }
  else
    n_netmask = xinet_pton((char *) TapOpt.Netmask.c_str());

  _fd = alloc(TapOpt.networkName, &device);
  _state = active;
  _id = db.size();
  _device = device;
  _networkName = TapOpt.networkName;
  _address = n_address;
  _netmask = n_netmask;
  _network = get_ip_address_network(n_address, n_netmask);

  configureDevice(device, TapOpt.Address, TapOpt.Netmask);
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
    _state = closing;
    return FAIL;
  }


  Log::Debug3("Read %d bytes packet from tap %s", packet->length, _device.c_str());
  return DONE;
}

bool
Taps::Tap::operator<< (Network::Packet * packet)
{
  if (!write(_fd, packet->buffer + 2, packet->length - 2)) {
    _state = closing;
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
  if (_state == active)
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

uChar
Taps::Tap::id () 
{
  return _id;
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

  std::vector < Taps::Tap * >::iterator it;

  Log::Debug2("freeing non active fd");

  it = db.begin();
  while (it != db.end()) {
    if (!(*it)->isActive()) {
      /* Remove network from peer */
      /* Send network remove packet to other peer */

      delete *it;
      it = db.erase(it);
    }
    else
      it++;
  }

  SetMaxFd();
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

std::vector<networkT>
Taps::getUserAllowedNetworks (std::string user)
{
  std::vector<Tap *>::iterator tapIt, tapEnd;
  std::vector<UserCredentialT>::const_iterator ucIt, ucEnd;
  std::vector<std::string>::const_iterator netIt, netEnd;

  std::vector<networkT>nl;
  networkT net;

  /* Get current user config */
  ucEnd = Options.UserCredentials().end();
  for (ucIt = Options.UserCredentials().begin(); ucIt < ucEnd; ++ucIt)
    if (!(*ucIt).Name.compare(user))
      break;

  /* For each network check if it is allowed in the AllowedNetworks list */
  tapEnd = db.end();
  for (tapIt = db.begin(); tapIt < tapEnd; ++tapIt) {
    netEnd = (*ucIt).AllowedNetworks.end();
    for (netIt = (*ucIt).AllowedNetworks.begin(); netIt < netEnd; ++netIt)
      if (!(*netIt).compare((*tapIt)->networkName())) {
        net.networkName = (*tapIt)->networkName();
        net.remoteId = (*tapIt)->id();
        net.address = (*tapIt)->address();
        net.netmask = (*tapIt)->netmask();

	nl.push_back(net);
        break;
      }
  }

  return nl;
}

void
Taps::setSystemRouting (Peers::Peer * peer, std::vector<networkT> allowedNets, char op)
{
  char route_command[256];

  char gateway[addressLenght + 1];
  char network[addressLenght + 1];
  char netmask[addressLenght + 1];

  std::vector<networkT> remoteNets;
  std::vector<networkT>::iterator allowedNetIt, allowedNetEnd;
  std::vector<networkT>::iterator remoteNetIt, remoteNetEnd;

  remoteNets = peer->nl();

  allowedNetEnd = allowedNets.end();
  for (allowedNetIt = allowedNets.begin(); allowedNetIt < allowedNetEnd; ++allowedNetIt) {

    inet_ntop(AF_INET, &(*allowedNetIt).address, gateway, addressLenght);

    remoteNetEnd = remoteNets.end();
    for (remoteNetIt = remoteNets.begin(); remoteNetIt < remoteNetEnd; ++remoteNetIt)
      if (!(*allowedNetIt).networkName.compare((*remoteNetIt).networkName)) {
        inet_ntop(AF_INET, &(*remoteNetIt).network, network, addressLenght);
        inet_ntop(AF_INET, &(*remoteNetIt).netmask, netmask, addressLenght);

        if (op == addRouting)
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
  std::vector<Tap *>::iterator tapIt, tapEnd;

  tapEnd = db.end();
  for (tapIt = db.begin(); tapIt < tapEnd; tapIt++)
    if (!(*tapIt)->networkName().compare(networkName))
      break;

  return (*tapIt)->id();
}
