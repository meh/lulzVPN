/*
 * "peer.cpp" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
 *
 * lulzVPN is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * lulzVPN is distributed in the hope that it will be useful,
 * but WITH ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */

#include <lulzvpn/lulzvpn.h>

#include <lulzvpn/config.h>
#include <lulzvpn/log.h>
#include <lulzvpn/networking.h>
#include <lulzvpn/peer_api.h>
#include <lulzvpn/protocol.h>
#include <lulzvpn/packet.h>
#include <lulzvpn/select.h>
#include <lulzvpn/tap_api.h>
#include <lulzvpn/xfunc.h>

std::vector < Peers::Peer * >Peers::db;
pthread_mutex_t Peers::db_mutex;

int Peers::maxTcpFd;
int Peers::maxUdpFd;

void
Peers::Register(Peer *p){

  db.push_back(p);

  Log::Debug2("Added fd %d to ctrl channel fd_set", p->tcpSd());
  FD_SET(p->tcpSd(), &Select::CtrlChannel::Set);
  SetMaxTcpFd();
  /* restart select thread so select() won't block world */
  Select::CtrlChannel::Restart();

  if(p->connType() == connected) {
    Log::Debug2("Added fd %d to data channel client fd_set", p->udpSd());
    FD_SET(p->udpSd(), &Select::DataChannel::Client::Set);
    SetMaxUdpFd();
    Select::DataChannel::Client::Restart();
  }

}

void
Peers::SetMaxTcpFd ()
{
  std::vector<Peer *>::iterator peerIt, peerEnd;
  maxTcpFd = 0;

  peerEnd = db.end();
  for (peerIt = db.begin(); peerIt < peerEnd; ++peerIt)
    if ((*peerIt)->tcpSd() > maxTcpFd)
      maxTcpFd = (*peerIt)->tcpSd();
}

void
Peers::SetMaxUdpFd ()
{
  std::vector<Peer *>::iterator peerIt, peerEnd;
  maxUdpFd = 0;

  peerEnd = db.end();
  for (peerIt = db.begin(); peerIt < peerEnd; ++peerIt)
    if ((*peerIt)->udpSd() > maxUdpFd)
      maxUdpFd = (*peerIt)->udpSd();
}

Peers::Peer::Peer(Connection con, std::string user, int address, std::vector<networkT> nl, char listenStat, bool connType)
{
  _tcpSd = con.tcpSd;
  _udpSd = (connType == connected ? con.udpSd : 0);

  _tcpSSL = con.tcpSSL;
  _udpSSL = con.udpSSL;

  _state = active;

  _address = address;
  _user = user;

  _nl = nl;
  _listeningStatus = listenStat;
  _connType = connType;

}

Peers::Peer::~Peer()
{
  FD_CLR(_tcpSd, &Select::CtrlChannel::Set);
  Log::Debug2("Removed fd %d from ctrl channel fd_set", _tcpSd);

  if(_connType == connected) {
    FD_CLR(_udpSd, &Select::DataChannel::Client::Set);
    Log::Debug2("Removed fd %d from data channel fd_set", _udpSd);
  }

  SSL_free(_tcpSSL);
  SSL_free(_udpSSL);

  close(_tcpSd);

  if(_connType == connected)
    close(_udpSd);

}

bool
Peers::Peer::operator>> (Packet::CtrlPacket *packet)
{
  if ((packet->length = xSSL_read(_tcpSSL, packet->buffer, Packet::TotLen, "forwarding data")) <= 0) {
    _state = closing;
    return FAIL;
  }

  Log::Debug3("Read %d bytes packet from peer %s (tcp)", packet->length, _user.c_str());
  return DONE;
}

bool
Peers::Peer::operator<< (Packet::CtrlPacket *packet)
{
  if (xSSL_write(_tcpSSL, packet->buffer, packet->length, "forwarding data") <= 0) {
    _state = closing;
    return FAIL;
  }

  Log::Debug3("\tForwarded to peer %s (tcp)", _user.c_str());
  return DONE;
}

bool
Peers::Peer::operator>> (Packet::DataPacket *packet)
{

  if ((packet->length = xSSL_read(_udpSSL, packet->buffer, Packet::TotLen, "forwarding data")) <= 0) {
//    _state = closing;
    return FAIL;
  }

  Log::Debug3("Read %d bytes packet from peer %s (udp)", packet->length, _user.c_str());
  return DONE;
}


bool
Peers::Peer::operator<< (Packet::DataPacket *packet)
{

  if (xSSL_write(_udpSSL, packet->buffer, packet->length, "forwarding data") <= 0) {
//    _state = closing;
    return FAIL;
  }

  Log::Debug3("\tForwarded to peer %s (udp)", _user.c_str());
  return DONE;
}

Packet::DataPacket *
Peers::Peer::decryptRawSSLPacket(Packet::DataPacket *rawPacket) {

  Packet::DataPacket *packet;

  packet = new Packet::DataPacket;

  BIO_write(SSL_get_rbio(_udpSSL), rawPacket->buffer, rawPacket->length);
  packet->length = SSL_read(_udpSSL, packet->buffer, Packet::TotLen);

  return packet;
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
Peers::Peer::isReadyToReadFromCtrlChannel (fd_set *rdSel)
{
  return FD_ISSET(_tcpSd, rdSel);
}

bool
Peers::Peer::isReadyToReadFromDataChannel (fd_set *rdSel)
{
  return FD_ISSET(_udpSd, rdSel);
}

bool
Peers::Peer::connType()
{
  return _connType;
}

void
Peers::Peer::setClosing ()
{
     _state = closing;
}

int
Peers::Peer::tcpSd ()
{
  return _tcpSd;
}

int
Peers::Peer::udpSd ()
{
  return _udpSd;
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

  SetMaxTcpFd();
  SetMaxUdpFd();
}

void
Peers::Peer::Disassociate ()
{
  Packet::CtrlPacket *disPacket;
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

