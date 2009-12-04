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

Taps::Tap  *Taps::db[MAX_TAPS];
pthread_mutex_t Taps::db_mutex;
int Taps::count;
int Taps::max_fd;

void
Taps::SetMaxFd ()
{

  int i;
  max_fd = 0;

  for (i = 0; i < count; i++)
    if (db[i]->fd() > max_fd)
      max_fd = db[i]->fd();
}

int
Taps::Tap::alloc (std::string *dev)
{

  /* TODO: add *bsd support */
  struct ifreq ifr;
  int fd, err;

  if ((fd = open ("/dev/net/tun", O_RDWR)) < 0)
    Log::Fatal ("Could not open /dev/net/tun device");

  memset (&ifr, 0, sizeof (ifr));

  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  strncpy (ifr.ifr_name, "lulz%d", IFNAMSIZ);

  if ((err = ioctl (fd, TUNSETIFF, (void *) &ifr)) < 0)
    {
      close (fd);
      Log::Fatal ("Could not allocate tap device");
    }

  dev->assign(ifr.ifr_name);
#ifdef DEBUG
  Log::Debug1 ("%s device create (fd %d).", dev->c_str(), fd);
#endif
  return fd;
}

Taps::Tap::Tap (std::string address, std::string netmask)
{

  int n_address;
  int n_netmask;
  std::string device;

  n_address = xinet_pton ((char *) address.c_str());

  if (netmask.empty())
    {
      n_netmask = get_ip_address_default_netmask (n_address);
      inet_ntop (AF_INET, &n_netmask, (char *) netmask.c_str(), ADDRESS_LEN);
    }
  else
    n_netmask = xinet_pton ((char *) netmask.c_str());

  _fd = alloc(&device);
  _state = TAP_ACTIVE;
  _device = device;
  _address = n_address;
  _netmask = n_netmask;

  configure_device (device, address, netmask);

  db[count] = this;

  count++;
  SetMaxFd ();

  FD_SET (_fd, &Network::master);
#ifdef DEBUG
  Log::Debug2 ("Added fd %d to fd_set master (1st free fd: %d)", _fd, count);
#endif

  Network::Server::RestartSelectLoop();
}


Taps::Tap::~Tap()
{

  FD_CLR (_fd, &Network::master);
  close (_fd);

#ifdef DEBUG
  Log::Debug2 ("Removed fd %d from fd_set master (current fd %d)", _fd, count);
#endif
}

bool
Taps::Tap::operator>> (Network::Packet * packet)
{
  if (!(packet->length = read (_fd,  packet->buffer + 1, 4095)))
    {
      _state = TAP_CLOSING;
      return FAIL;
    }

#ifdef DEBUG
  Log::Debug3 ("Read %d bytes packet from tap %s", packet->length, _device.c_str());
#endif
  return DONE;
}

bool
Taps::Tap::operator<< (Network::Packet * packet)
{
  if (!write (_fd, packet->buffer + 1, packet->length - 1))
    {
      _state = TAP_CLOSING;
      return FAIL;
    }

#ifdef DEBUG
  Log::Debug3 ("\tForwarded to tap %s", _device.c_str());
#endif
  return DONE;
}

bool
Taps::Tap::isActive ()
{
  if (_state == TAP_ACTIVE)
    return true;

  return false;
}

bool
Taps::Tap::isReadyToRead(fd_set *rd_sel)
{
  if (FD_ISSET (_fd, rd_sel))
    return true;

  return false;
}

void
Taps::Tap::showInfo()
{

}

int Taps::Tap::fd ()
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

void
Taps::FreeNonActive ()
{

  int i;

  for (i = 0; i < MAX_TAPS; i++)
    if (!db[i]->isActive())
      {
        delete db[i];
        db[i] = NULL;
      }

  RebuildDb();
}

void
Taps::RebuildDb ()
{
  int i;
  int j;
  int freed_tap;

  freed_tap = 0;
  j = 0;

  for (i = 0; i < count; i++)
    if (db[i] != NULL)
      db[j++] = db[i];
    else
      freed_tap++;

  count -= freed_tap;
  SetMaxFd ();
}

int
Taps::get_ip_address_default_netmask (int address)
{
  u_char *c_addr;
  int netmask;

  c_addr = (u_char *) & address;

  if (c_addr[0] < (u_char) 128)
    netmask = 0xff000000;
  else if (c_addr[0] < (u_char) 192)
    netmask = 0xffff0000;
  else
    netmask = 0xffffff00;

  return netmask;
}

int
Taps::getCidrNotation(int netmask){

     int cidrNetmask = 32;

     while(!(netmask & 1)){
	  netmask >>= 1;
	  cidrNetmask--;
     }

     return cidrNetmask;
}

int
Taps::configure_device (std::string device, std::string address, std::string netmask)
{
  char ifconfig_command[256];

  sprintf (ifconfig_command, "ifconfig %s %s netmask %s", device.c_str(), address.c_str(), netmask.c_str());
  system (ifconfig_command);

#ifdef DEBUG
          Log::Debug2("Ifconfig command: %s",ifconfig_command);
#endif

  return 1;
}

net_ls_t
Taps::get_user_allowed_networks (std::string user __attribute__ ((unused)))
{
  int i;
  net_ls_t nl;

  /* TODO: free all this stuff */
  nl.device = new std::string[count];
  nl.address = new int[count];
  nl.netmask = new int[count];

  nl.count = count;

  for (i = 0; i < count; i++)
    {
      /* TODO:add acl check */
      nl.device[i] = db[i]->device();
      nl.address[i] = db[i]->address();
      nl.netmask[i] = db[i]->netmask();
    }

  return nl;
}

void
Taps::set_system_routing (Peers::Peer * peer, char op)
{
  char route_command[256];

  char gateway[ADDRESS_LEN + 1];
  char network[ADDRESS_LEN + 1];
  char netmask[ADDRESS_LEN + 1];

  net_ls_t local_nl;
  net_ls_t remote_nl;

  int i;
  int j;

  local_nl = get_user_allowed_networks (peer->user());
  remote_nl = peer->nl();

  for (i = 0; i < local_nl.count; i++)
    {

      inet_ntop (AF_INET, &local_nl.address[i], gateway, ADDRESS_LEN);

      for (j = 0; j < remote_nl.count; j++)
        {
          inet_ntop (AF_INET, &remote_nl.network[j], network, ADDRESS_LEN);
          inet_ntop (AF_INET, &remote_nl.netmask[j], netmask, ADDRESS_LEN);

          if (op == ADD_ROUTING)
            sprintf (route_command,
                     "route add -net %s netmask %s gw %s", network,
                     netmask, gateway);
          else
            sprintf (route_command,
                     "route del -net %s netmask %s gw %s", network,
                     netmask, gateway);

#ifdef DEBUG
          Log::Debug2("Route command: %s",route_command);
#endif
          system (route_command);
        }
    }
}

