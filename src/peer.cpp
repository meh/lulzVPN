/*
 * "peer.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
 *
 * lulzNet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * lulzNet is distributed in the hope that it will be useful,
 * but WITH ANY WARRANTY; without even the implied warranty of
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

std::vector < Peers::Peer * >Peers::db;
pthread_mutex_t Peers::db_mutex;

int Peers::maxFd;

void
Peers::SetMaxFd ()
{
  uInt i;
  maxFd = 0;

  for (i = 0; i < db.size(); i++)
    if (db[i]->fd() > maxFd)
      maxFd = db[i]->fd();
}

Peers::Peer::Peer(int fd, SSL * ssl, std::string user, int address, networkT nl)
{
  _fd = fd;
  _ssl = ssl;

  _state = PEER_ACTIVE;

  _address = address;
  _user = user;

  _nl = nl;

  db.push_back(this);

  SetMaxFd();

  FD_SET(_fd, &Network::master);

  Log::Debug2("Added fd %d to fd_set master (1st free fd: %d)", fd, db.size());

  /* restart select thread so select() won't block world */
  Network::Server::RestartSelectLoop();
}


Peers::Peer::~Peer()
{
  SSL_free(_ssl);

  FD_CLR(_fd, &Network::master);
  close(_fd);


  Log::Debug2("Removed fd %d from fd_set master (current fd %d)", _fd, db.size());
}

bool
Peers::Peer::operator>> (Network::Packet * packet)
{
  if (!(packet->length = xSSL_read(_ssl, packet->buffer, 4096, "forwarding data"))) {
    _state = PEER_CLOSING;
    return FAIL;
  }


  Log::Debug3("Read %d bytes packet from peer %s", packet->length, _user.c_str());
  return DONE;
}

bool
Peers::Peer::operator<< (Network::Packet * packet)
{
  if (!xSSL_write(_ssl, packet->buffer, packet->length + 2, "forwarding data")) {
    _state = PEER_CLOSING;
    return FAIL;
  }


  Log::Debug3("\tForwarded to peer %s", _user.c_str());
  return DONE;
}

bool
Peers::Peer::isRoutableAddress (int address)
{
  uInt i;
  for (i = 0; i < _nl.networkName.size(); i++)
    if (_nl.network[i] == get_ip_address_network(address, _nl.netmask[i]))
      return true;

  return false;
}

bool
Peers::Peer::isActive ()
{
  if (_state == PEER_ACTIVE)
    return true;

  return false;
}

bool
Peers::Peer::isReadyToRead (fd_set * rdSel)
{
  if (FD_ISSET(_fd, rdSel))
    return true;

  return false;
}

void
Peers::Peer::setClosing ()
{
  _state = PEER_CLOSING;
}

int
Peers::Peer::fd ()
{
  return _fd;
}

std::string
Peers::Peer::user ()
{

  return _user;
}

int
Peers::Peer::address ()
{
  return _address;
}

networkT
Peers::Peer::nl ()
{
  return _nl;
}


void
Peers::FreeNonActive ()
{
  uInt i;
  std::vector < Peers::Peer * >::iterator it;

  Log::Debug2("freeing non active fd");
  for (i = 0; i < db.size(); i++)
    if (!db[i]->isActive()) {
      Taps::setSystemRouting(db[i], Taps::getUserAllowedNetworks(db[i]->user()), DEL_ROUTING);
      delete db[i];

      it = db.begin();
      it += i;
      db.erase(it);
      SetMaxFd();
    }
}

void
Peers::Peer::Disassociate ()
{
  char packet[3];

  packet[0] = CONTROL_PACKET;
  packet[1] = CLOSE_CONNECTION;
  xSSL_write(_ssl, packet, 2, "disconnection packet");

  Taps::setSystemRouting(this, Taps::getUserAllowedNetworks(_user), DEL_ROUTING);
  delete this;
}

int
Peers::UserIsConnected (std::string user)
{
  unsigned int i;

  for (i = 0; i < db.size(); i++)
    if (db[i]->isActive())
      if (!db[i]->user().compare(user))
        return TRUE;

  return FALSE;
}
