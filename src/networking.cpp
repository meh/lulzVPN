/*
 *"networking.c" (C) blawl ( j[dot] segf4ult[at] gmail[dot] com )
 *
 *lulzNet is free software; you can redistribute it and / or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 *lulzNet is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *MA 02110 - 1301, USA.
 */

#include <lulznet/lulznet.h>

#include <lulznet/auth.h>
#include <lulznet/config.h>
#include <lulznet/log.h>
#include <lulznet/networking.h>
#include <lulznet/peer.h>
#include <lulznet/protocol.h>
#include <lulznet/packet.h>
#include <lulznet/tap.h>

SSL_CTX * Network::Client::sslCTX;
SSL_CTX *Network::Server::sslCTX;

fd_set Network::master;
pthread_t Network::Server::select_t;

void
Network::Server::sslInit ()
{
  Network::Server::sslCTX = SSL_CTX_new(SSLv23_server_method());
  if (!Network::Server::sslCTX)
    Log::Fatal("Failed to do SSL CTX new");

  Log::Debug2("Loading SSL certificate");
  if (SSL_CTX_use_certificate_file(Network::Server::sslCTX, CERT_FILE, SSL_FILETYPE_PEM) <= 0)
    Log::Fatal("Failed to load SSL certificate %s", CERT_FILE);

  Log::Debug2("Loading SSL private key");
  if (SSL_CTX_use_PrivateKey_file(Network::Server::sslCTX, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
    Log::Fatal("Failed to load SSL private key %s", KEY_FILE);
}

void
Network::Client::sslInit ()
{
  Network::Client::sslCTX = SSL_CTX_new(SSLv23_client_method());
}

void *
Network::Server::ServerLoop (void *arg __attribute__ ((unused)))
{

  int listenSock;
  int peerSock;
  int on = 1;
  SSL *peerSsl;
  char peer_address[addressLenght + 1];
  struct sockaddr_in server;
  struct sockaddr_in peer;
  socklen_t addrSize;
  pthread_t connectQueueT;
  HandshakeOptionT *hsOpt;
  Peers::Peer * newPeer;
  if ((listenSock = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    Log::Fatal("cannot create socket");

  Log::Debug2("listenSock (fd %d) created", listenSock);
  if (setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
    Log::Error("setsockopt SO_REUSEADDR: %s", strerror(errno));

  server.sin_family = AF_INET;
  server.sin_port = htons(Options.BindingPort());
  server.sin_addr.s_addr = INADDR_ANY;   /*(server_opt->binding_address); */
  memset(&(server.sin_zero), '\0', 8);

  Log::Debug2("Binding port %d", port);
  if (bind(listenSock, (struct sockaddr *) &server, sizeof(struct sockaddr)) == -1)
    Log::Fatal("cannot binding to socket");

  Log::Debug1("Listening");
  if (listen(listenSock, maxAcceptedConnections) == -1)
    Log::Fatal("cannot listen");

  addrSize = sizeof(struct sockaddr_in);
  /* @TODO while(available_connection()) else sleep && goto! */
  while (1) {
    if ((peerSock = accept(listenSock, (struct sockaddr *) &peer, &addrSize)) == -1)
      Log::Fatal("cannot accept");

    Protocol::SendBanner(peerSock);
    try {
    hsOpt = new HandshakeOptionT;
    } catch(const std::bad_alloc& x) {
      Log::Fatal("Out of memory");
    }

    if ((peerSsl = SSL_new(Network::Server::sslCTX)) != NULL) {
      SSL_set_fd(peerSsl, peerSock);

      Log::Debug2("SSL Handshake");
      if (SSL_accept(peerSsl) > 0) {
        if (Protocol::Server::Handshake(peerSsl, hsOpt)) {
          pthread_mutex_lock(&Peers::db_mutex);

	  try {
          newPeer = new Peers::Peer(peerSock, peerSsl, hsOpt->peer_username, peer.sin_addr.s_addr, hsOpt->remoteNets);
	  Peers::Register(newPeer);
	  } catch(const std::bad_alloc& x) {
	    Log::Fatal("Out of memory");
	  }

          inet_ntop(AF_INET, &peer.sin_addr.s_addr, peer_address, addressLenght);
          Log::Info("Connection accepted from %s (fd %d)", peer_address, peerSock);

          /* Set routing */
          Log::Debug2("Setting Routing");
          Taps::setSystemRouting(newPeer, hsOpt->allowedNets, addRouting);

          pthread_mutex_unlock(&Peers::db_mutex);

          pthread_create(&connectQueueT, NULL, CheckConnectionsQueue, &hsOpt->userLs);
          pthread_join(connectQueueT, NULL);
          delete hsOpt;
        }
        else {
          Log::Error("Cannot complete handshake");
          SSL_free(peerSsl);
          close(peerSock);
          delete hsOpt;
        }
      }
      else {
        Log::Error("Cannot complete SSL handshake");
        close(peerSock);
        delete hsOpt;
      }
    }
    else {
      Log::Error("Cannot create new SSL");
      close(peerSock);
      delete hsOpt;
    }
  }
  return NULL;
}

int
Network::LookupAddress (std::string address)
{

  struct hostent *host_info;

  Log::Debug1("Looking up client %s", address.c_str());
  host_info = gethostbyname(address.c_str());
  if (host_info == NULL) {
    Log::Error("Cannot lookup hostname", 1);
    return 0;
  }

  return *((int *) host_info->h_addr);
}

void
Network::Client::PeerConnect (int address, short port)
{

  struct sockaddr_in peer;
  int peerSock;
  SSL *peerSsl;
  HandshakeOptionT hsOpt;

  pthread_t connectQueueT;
  Peers::Peer * newPeer;
  if ((peerSock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    Log::Error("cannot create socket", 1);
    return;
  }

  Log::Debug2("peer sock (fd %d) created", peerSock);

  peer.sin_family = AF_INET;
  peer.sin_port = htons(port ? port : port);
  peer.sin_addr.s_addr = address;
  memset(&(peer.sin_zero), '\0', 8);

  if (connect(peerSock, (struct sockaddr *) &peer, sizeof(peer)) == -1) {
    Log::Error("Cannot connect", 1);
    return;
  }

  Protocol::RecvBanner(peerSock);
  if ((peerSsl = SSL_new(Network::Client::sslCTX)) != NULL) {
    SSL_set_fd(peerSsl, peerSock);
    Log::Debug2("SSL Handshake");
    if (SSL_connect(peerSsl) > 0) {
      if (Network::VerifySslCert(peerSsl)) {
        if (Protocol::Client::Handshake(peerSsl, &hsOpt)) {
          pthread_mutex_lock(&Peers::db_mutex);
          
	  try{
          newPeer = new Peers::Peer(peerSock, peerSsl, hsOpt.peer_username, address, hsOpt.remoteNets);
	  Peers::Register(newPeer);
	  } catch(const std::bad_alloc& x){
	    Log::Fatal("Out of memory");
	  }

          Log::Info("Connected");

          Log::Debug2("Setting Routing");
          Taps::setSystemRouting(newPeer, hsOpt.allowedNets, addRouting);

          pthread_mutex_unlock(&Peers::db_mutex);

          pthread_create(&connectQueueT, NULL, Network::CheckConnectionsQueue, &hsOpt.userLs);
          pthread_join(connectQueueT, NULL);

        }
        else {
          Log::Error("Cannot complete lulznet handshake");
          SSL_free(peerSsl);
          close(peerSock);
        }
      }
      else {
        Log::Error("Cannot verify host identity");
        SSL_free(peerSsl);
        close(peerSock);
      }
    }
    else {
      Log::Error("Cannot complete SSL handshake");
      SSL_free(peerSsl);
      close(peerSock);
    }
  }
  else {
    Log::Error("Cannot creane new SSL");
    close(peerSock);
  }
}

void *
Network::Server::SelectLoop (void __attribute__ ((unused)) * arg)
{
  Packet packet;
  int ret;
  int freeFdFlag;
  fd_set readSelect;
  int maxFd;
  std::vector<Peers::Peer*>::iterator peerIt, peerEnd;
  std::vector<Taps::Tap*>::iterator tapIt, tapEnd;

  int dont_close_flag = 1;
  while (dont_close_flag) {
    pthread_mutex_lock(&Peers::db_mutex);
    readSelect = Network::master;
    freeFdFlag = 0;
    maxFd = (Peers::maxFd > Taps::maxFd ? Peers::maxFd : Taps::maxFd);
    pthread_mutex_unlock(&Peers::db_mutex);

    ret = select(maxFd + 1, &readSelect, NULL, NULL, NULL);

    pthread_mutex_lock(&Peers::db_mutex);
    if (ret == -1) 
      Log::Fatal("Select Log::Error");

    else {
      peerEnd = Peers::db.end();
      for (peerIt = Peers::db.begin(); peerIt < peerEnd; ++peerIt) { 
        if((*peerIt)->isReadyToRead(&readSelect)) {
          if ((*peerIt)->isActive()) {
            if (**peerIt >> &packet) {
              switch (packet.buffer[0]) {
              case dataPacket:
                Network::Server::ForwardToTap(&packet, *peerIt);
                break;
              case controlPacket:
                if (packet.buffer[1] == closeConnection) {
                  Log::Debug3("control_packet: closing connection");
                  freeFdFlag = 1;
                  (*peerIt)->setClosing();
                  freeFdFlag = true;
                }
                else {
                  Log::Error("Unknow control flag");
		}
	      }
	    }
	  }
	}
      }

      /* Check if is present some non active peer */
      if (freeFdFlag) {
        Peers::FreeNonActive();
      }

      tapEnd = Taps::db.end();
      for (tapIt = Taps::db.begin(); tapIt < tapEnd; ++tapIt) {
        if ((*tapIt)->isReadyToRead(&readSelect)) {
          if ((*tapIt)->isActive()) {
            if (**tapIt >> &packet) {
              Network::Server::ForwardToPeer(&packet, (uChar) (*tapIt)->id());
	    }
	  }
	}
      }

    /* When the cycle is end functions can modify the fd_db structure */
    pthread_mutex_unlock(&Peers::db_mutex);
    }
  }
  return NULL;
}

void
Network::Server::RestartSelectLoop ()
{

  Log::Debug2("Restarting select()");
  if (Network::Server::select_t != (pthread_t) NULL) {
    if (pthread_cancel(Network::Server::select_t)) 
      Log::Fatal("Cannot cancel select thread");
    else 
      pthread_create(&Network::Server::select_t, NULL, Network::Server::SelectLoop, NULL);
  }
}

inline void
Network::Server::ForwardToTap (Network::Packet * packet, Peers::Peer * src)
{

  uChar i;
  std::vector<networkT>::const_iterator netIt, netEnd;
  int nAddr;
  Taps::Tap *tap;

  nAddr = PacketInspection::GetDestinationIp(packet);
  i = packet->buffer[1];
  tap = Taps::db[i];

  if (tap->isActive()) {
    if (tap->isRoutableAddress(nAddr)) {
      netEnd = src->nl().end();
      for (netIt = src->nl().begin(); netIt < netEnd; ++netIt) {
        if ((*netIt).localId == i) {
          *tap << packet;
          break;
        }
      }
    }
  }

  Log::Dump(packet->buffer, packet->length);
}

inline void
Network::Server::ForwardToPeer (Network::Packet * packet, uChar localId)
{

  std::vector<Peers::Peer *>::iterator peerIt, peerEnd;
  std::vector<networkT>::const_iterator netIt, netEnd;
  int nAddr;

  nAddr = PacketInspection::GetDestinationIp(packet);
  packet->buffer[0] = dataPacket;
  packet->buffer[1] = localId;

  peerEnd = Peers::db.end();
  for (peerIt = Peers::db.begin(); peerIt < peerEnd; ++peerIt) {
    if ((*peerIt)->isActive()) {
      if ((*peerIt)->isRoutableAddress(nAddr)) {
        netEnd = (*peerIt)->nl().end();
        for (netIt = (*peerIt)->nl().begin(); netIt < netEnd; ++netIt) {
          if ((*netIt).localId == localId) {
            **peerIt << packet;
            break;
          }
	}
      }
    }
  }

  Log::Dump(packet->buffer, packet->length);
}

int
Network::VerifySslCert (SSL * ssl)
{
  char *fingerprint;
  char answer = 'y';
  if (SSL_get_verify_result(ssl) != X509_V_OK) {
    fingerprint = Auth::Crypt::GetFingerprintFromCtx(ssl);
    std::cout << "Could not verify SSL servers certificate (self signed)." << std::endl;
    std::cout << "Fingerprint is: " << fingerprint << std::endl;
    std::cout << "Do you want to continue? [y|n]: y\n";
//    std::cin >> answer;

    delete[] fingerprint;

    return ((answer == 'y') ? true : false);
  }

  return true;
}

void *
Network::CheckConnectionsQueue (void *arg)
{

  std::vector<userT> *userLs;
  std::vector<userT>::iterator userIt, userEnd;

  userLs = (std::vector<userT> *) arg;

  userEnd = userLs->end();
  for (userIt = userLs->begin(); userIt < userEnd; ++userIt)
    if (!Peers::UserIsConnected((*userIt).user))
      Network::Client::PeerConnect((*userIt).address, port);

  return NULL;
}
