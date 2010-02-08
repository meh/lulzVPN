/*
 * "peer.cpp" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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
#include <lulznet/packet.h>
#include <lulznet/tap.h>
#include <lulznet/xfunc.h>

std::vector < Peers::Peer * >Peers::db;
pthread_mutex_t Peers::db_mutex;
int Peers::maxFd;

void
Peers::Register(Peer *p){

  db.push_back(p);

  Log::Debug2("Added fd %d to fd_set master", p->fd());
  FD_SET(p->fd(), &Network::master);

  SetMaxFd();

  /* restart select thread so select() won't block world */
  Network::Server::RestartSelectLoop();
}

void
Peers::SetMaxFd ()
{
  std::vector<Peer *>::iterator peerIt, peerEnd;
  maxFd = 0;

  peerEnd = db.end();
  for (peerIt = db.begin(); peerIt < peerEnd; ++peerIt)
    if ((*peerIt)->fd() > maxFd)
      maxFd = (*peerIt)->fd();
}

Peers::Peer::Peer(int fd, SSL *ssl, std::string user, int address, std::vector<networkT> nl, char listenStat)
{
  _fd = fd;
  _ssl = ssl;

  _state = active;

  _address = address;
  _user = user;

  _nl = nl;
  _listeningStatus = listenStat;

}


Peers::Peer::~Peer()
{
  SSL_free(_ssl);

  FD_CLR(_fd, &Network::master);
  close(_fd);


  Log::Debug2("Removed fd %d from fd_set master (current fd %d)", _fd, db.size());
}

bool
Peers::Peer::operator>> (Packet::Packet *packet)
{
  if (!(packet->length = xSSL_read(_ssl, packet->buffer, 4096, "forwarding data"))) {
    _state = closing;
    return FAIL;
  }

  Log::Debug3("Read %d bytes packet from peer %s", packet->length, _user.c_str());
  return DONE;
}

bool
Peers::Peer::operator<< (Packet::Packet *packet)
{
  if (!xSSL_write(_ssl, packet->buffer, packet->length + 2, "forwarding data")) {
    _state = closing;
    return FAIL;
  }

  Log::Debug3("\tForwarded to peer %s", _user.c_str());
  return DONE;
}

bool
Peers::Peer::isRoutableAddress (int address)
{
  std::vector<networkT>::iterator netIt, netEnd;

  netEnd = _nl.end();
  for (netIt = _nl.begin(); netIt < netEnd; netIt++)
    if ((*netIt).network == get_ip_address_network(address, (*netIt).netmask))
      return true;

  return false;
}

bool
Peers::Peer::isListening ()
{
  return _listeningStatus;
}

bool
Peers::Peer::isActive ()
{
  if (_state == active)
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
     _state = closing;
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

const std::vector<networkT>&
Peers::Peer::nl ()
{
  return _nl;
}

void
Peers::FreeNonActive ()
{
  std::vector<Peer*>::iterator it;
 
  Log::Debug2("freeing non active fd");

  it = db.begin();
  while(it != db.end()) {
    if (!(*it)->isActive()) {
      Taps::setSystemRouting((*it), Taps::getUserAllowedNetworks((*it)->user()), delRouting);

      delete *it;
      it = db.erase(it);
    }
    else
      it++;
  }

  SetMaxFd();
}

void
Peers::Peer::Disassociate ()
{
  Packet::Packet *disPacket;
  disPacket = Packet::BuildDisassociationPacket();
  *this << disPacket;

  Taps::setSystemRouting(this, Taps::getUserAllowedNetworks(_user), delRouting);
  delete disPacket;
  delete this;
}

int
Peers::UserIsConnected (std::string user)
{
  std::vector<Peer *>::iterator peerIt, peerEnd;

  peerEnd = db.end();
  for (peerIt = db.begin(); peerIt < peerEnd; ++peerIt)
    if ((*peerIt)->isActive())
      if (!(*peerIt)->user().compare(user))
        return true;

  return false;
}
