/*
 *"networking.cpp" (C) blawl ( j[dot] segf4ult[at] gmail[dot] com )
 *
 *lulzVPN is free software; you can redistribute it and / or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 *lulzVPN is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *MA 02110 - 1301, USA.
 */

#include <lulzvpn/lulzvpn.h>

#include <lulzvpn/auth.h>
#include <lulzvpn/config.h>
#include <lulzvpn/log.h>
#include <lulzvpn/networking.h>
#include <lulzvpn/peer_api.h>
#include <lulzvpn/protocol.h>
#include <lulzvpn/packet.h>
#include <lulzvpn/select.h>
#include <lulzvpn/tap_api.h>

fd_set Select::TapChannel::Set;
fd_set Select::CtrlChannel::Set;
fd_set Select::DataChannel::Client::Set;

pthread_t Select::TapChannel::ThreadId;
pthread_t Select::CtrlChannel::ThreadId;
pthread_t Select::DataChannel::Client::ThreadId;
pthread_t Select::DataChannel::Server::ThreadId;

int udpDataSock;

void *
Select::DataChannel::Server::Loop(void __attribute__ ((unused)) *arg) {
  Packet::DataPacket rawPacket;
  Packet::DataPacket *packet;
  std::vector<Peers::Peer*>::iterator peerIt, peerEnd;
  struct sockaddr_in peer;
  int peerLen = sizeof(peer);

  Log::Debug2("Starting server data channel loop");
  while (true) {

    rawPacket.length = recvfrom(udpDataSock, rawPacket.buffer, Packet::PldLen, 0,(struct sockaddr *) &peer, (socklen_t*)&peerLen);

    if (rawPacket.length <= 0) { 
      Log::Error("Cannot recv from server data channel");
      continue;
    }

    peerEnd = Peers::db.end();
    for (peerIt = Peers::db.begin(); peerIt < peerEnd; ++peerIt) { 
      if(((*peerIt)->address() == (int) peer.sin_addr.s_addr) && (*peerIt)->isActive()) {
        packet = (*peerIt)->decryptRawSSLPacket(&rawPacket);
	Log::Debug3("Read %d bytes packet from peer %s",packet->length,(*peerIt)->user().c_str());

        Network::ForwardToTap(packet, (*peerIt));
	delete packet;

        break;
      }
    }
  }
  return NULL;
}

void *
Select::DataChannel::Client::Loop(void __attribute__ ((unused)) *arg) {

  Packet::DataPacket packet;
  std::vector<Peers::Peer*>::iterator peerIt, peerEnd;
  int ret;
  fd_set CopySet;

  Log::Debug2("Starting data channel client loop");
  while (true) {

    CopySet = Set;

    ret = select(Peers::maxUdpFd + 1, &CopySet, NULL, NULL, NULL);
    printf("DataChannel select returns %d\n",ret);
    if(ret == -1)
      Log::Fatal("Udp Select error");

    int i;

    peerEnd = Peers::db.end();
    for (peerIt = Peers::db.begin(), i = 0; peerIt < peerEnd; ++peerIt, ++i) { 
      printf("I: %d peerIt<peerEnd: %d\n",i,  peerIt < peerEnd);
      if((*peerIt)->isReadyToReadFromDataChannel(&CopySet) && (*peerIt)->isActive()) {
        if (**peerIt >> &packet) 
          Network::ForwardToTap(&packet, (*peerIt));

	break;
      }
    }
  }
  return NULL;
}

void *
Select::CtrlChannel::Loop(void __attribute__ ((unused)) *arg) {

  Packet::CtrlPacket packet;
  std::vector<Peers::Peer*>::iterator peerIt, peerEnd;
  int ret;
  int peerClosingFlag;
  fd_set CopySet;

  Log::Debug2("Starting ctrl channel loop");
  while (true) {

    peerClosingFlag = 0;

    pthread_mutex_lock(&Peers::db_mutex);
    CopySet = Set;
    pthread_mutex_unlock(&Peers::db_mutex);

    ret = select(Peers::maxTcpFd + 1, &CopySet, NULL, NULL, NULL);
    printf("CtrlChannel select returns %d\n",ret);

    pthread_mutex_lock(&Peers::db_mutex);
    if (ret == -1) 
      Log::Fatal("Tcp Select Error");

    peerEnd = Peers::db.end();
    for (peerIt = Peers::db.begin(); peerIt < peerEnd; ++peerIt) { 
      if((*peerIt)->isReadyToReadFromCtrlChannel(&CopySet) && (*peerIt)->isActive()) {
        if (**peerIt >> &packet) {
          switch (packet.buffer[0]) {
            case closeConnection:
              Network::HandleClosingConnection(*peerIt,&peerClosingFlag);
              break;
            case newPeerNotify:
              Network::HandleNewPeerNotify(&packet);
              break;
            default:
              Log::Error("Unknow control flag");
           } 
         }
       }
     }

    /* Check if is present some non active peer */
    if (peerClosingFlag)
      Peers::FreeNonActive();

    /* When the cycle is end functions can modify the fd_db structure */
    pthread_mutex_unlock(&Peers::db_mutex);
  }
  return NULL;
}

void *
Select::TapChannel::Loop(void __attribute__ ((unused)) *arg) {
  Packet::DataPacket packet;
  std::vector<Taps::Tap*>::iterator tapIt, tapEnd;
  int ret;
  fd_set CopySet;

  Log::Debug2("Starting tap channel loop");
  while (true) {

    CopySet = Set;
    ret = select(Taps::maxFd + 1, &CopySet, NULL, NULL, NULL);
    printf("TapChannel select returns %d\n",ret);

    if (ret == -1) 
      Log::Fatal("Tap Select Error");

    tapEnd = Taps::db.end();
    for (tapIt = Taps::db.begin(); tapIt < tapEnd; ++tapIt) {
      if (((*tapIt)->isReadyToRead(&CopySet)) && (*tapIt)->isActive()) {
        if (**tapIt >> &packet) {
          Network::ForwardToPeer(&packet, (uChar) (*tapIt)->id());
        }
      }
    }
  }
  return NULL;
}

void
Select::DataChannel::Client::Restart ()
{
  if (ThreadId != (pthread_t) NULL) {
    Log::Debug2("Restarting data client select()");
    if (pthread_cancel(ThreadId)) 
      Log::Fatal("Cannot cancel select thread");
    
    pthread_create(&ThreadId, NULL, Loop, NULL);
  }
}

void
Select::CtrlChannel::Restart ()
{
  if (ThreadId != (pthread_t) NULL) { 
    Log::Debug2("Restarting ctrl select()");
    if (pthread_cancel(ThreadId)) 
      Log::Fatal("Cannot cancel select thread");

    pthread_create(&ThreadId, NULL, Loop, NULL);
  }
}

void
Select::TapChannel::Restart ()
{
  if (ThreadId != (pthread_t) NULL) { 
    Log::Debug2("Restarting tap select()");
    if (pthread_cancel(ThreadId)) 
      Log::Fatal("Cannot cancel select thread");

    pthread_create(&ThreadId, NULL, Loop, NULL);
  }
}

