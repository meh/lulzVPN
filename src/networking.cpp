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

SSL_CTX *Network::Client::TcpSSLCtx;
SSL_CTX *Network::Server::TcpSSLCtx;

SSL_CTX *Network::Client::UdpSSLCtx;
SSL_CTX *Network::Server::UdpSSLCtx;

pthread_t Network::Server::ServerLoopT;

void
Network::Server::sslInit ()
{
  /* tcp SSL ctx */
  Network::Server::TcpSSLCtx = SSL_CTX_new(SSLv23_server_method());
  if (!TcpSSLCtx)
    Log::Fatal("Failed to do SSL CTX new");

  Log::Debug2("Loading SSL certificate");
  if (SSL_CTX_use_certificate_file(TcpSSLCtx, CERT_FILE, SSL_FILETYPE_PEM) <= 0)
    Log::Fatal("Failed to load SSL certificate %s", CERT_FILE);

  Log::Debug2("Loading SSL private key");
  if (SSL_CTX_use_PrivateKey_file(TcpSSLCtx, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
    Log::Fatal("Failed to load SSL private key %s", KEY_FILE);

  /* udp SSL ctx */
  UdpSSLCtx = SSL_CTX_new(DTLSv1_server_method());
  if (!UdpSSLCtx)
    Log::Fatal("Failed to do SSL CTX new");

  Log::Debug2("Loading SSL certificate");
  if (SSL_CTX_use_certificate_file(UdpSSLCtx, CERT_FILE, SSL_FILETYPE_PEM) <= 0)
    Log::Fatal("Failed to load SSL certificate %s", CERT_FILE);

  Log::Debug2("Loading SSL private key");
  if (SSL_CTX_use_PrivateKey_file(UdpSSLCtx, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
    Log::Fatal("Failed to load SSL private key %s", KEY_FILE);

  SSL_CTX_set_read_ahead(UdpSSLCtx, 1);
}

void
Network::Client::sslInit ()
{
  TcpSSLCtx = SSL_CTX_new(SSLv23_client_method());
  UdpSSLCtx = SSL_CTX_new(DTLSv1_client_method());

  SSL_CTX_set_read_ahead(UdpSSLCtx, 1);
}

void * 
Network::Server::ServerLoop (void *arg __attribute__ ((unused)))
{

  Peers::Connection con;
  char peerAddress[addressLenght + 1];
  int listenTcpSock;
  int listenUdpHandshakeSock;
  struct sockaddr_in tcpServer;
  struct sockaddr_in udpServer;
  struct sockaddr_in peer;
  int on = 1;
  short remotePort;
  BIO *udpBio;
  BIO *memBio;

  socklen_t addrSize;
  pthread_t connectQueueT;
  HandshakeOptionT *hsOpt;
  Peers::Peer * newPeer;

  addrSize = sizeof(udpServer);

  /* 
   * We have two listening socket:
   * - listenTcpSock, which is the listener for the reilable/control channel
   * - listenUdpHandshakeSock, which is the listener for the udp ssl handshake
   */

  tcpServer.sin_family = AF_INET;
  tcpServer.sin_port = htons(Options.BindingPort());
  tcpServer.sin_addr.s_addr = INADDR_ANY;   /*(tcpServer.opt->binding_address); */
  memset(&(tcpServer.sin_zero), '\0', 8);

  udpServer.sin_family = AF_INET;
  udpServer.sin_port = htons(Options.BindingPort());
  udpServer.sin_addr.s_addr = INADDR_ANY;   //(udpServer.opt->binding_address); 
  memset(&(udpServer.sin_zero), '\0', 8);

  /* Tcp stuff initialization */

  if ((listenTcpSock = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    Log::Fatal("cannot create socket");
  Log::Debug2("listenTcpSock (sd %d) created", listenTcpSock);

  if (setsockopt(listenTcpSock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
    Log::Error("setsockopt SO_REUSEADDR: %s", strerror(errno));

  Log::Debug2("Binding tcp port %d", Options.BindingPort());
  if (bind(listenTcpSock, (struct sockaddr *) &tcpServer, addrSize) == -1)
    Log::Fatal("cannot binding to tcp socket");

  if(listen(listenTcpSock,16) == -1)
    Log::Fatal("Cannot listen");

  /* Udp stuff initialization */

  if((listenUdpHandshakeSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
     Log::Fatal("cannot create udp socket");
  Log::Debug2("listenUdpHandshakeSock (sd %d) created", listenUdpHandshakeSock);

  Log::Debug2("Binding udp port %d", Options.BindingPort());
  if (bind(listenUdpHandshakeSock,(struct sockaddr *) &udpServer, addrSize)==-1)
    Log::Fatal("cannot binding to socket");

  Log::Info("Listening for connections");
  while (1) {
    if ((con.tcpSd = accept(listenTcpSock, (struct sockaddr *) &peer, &addrSize)) == -1)
      Log::Fatal("cannot accept");

    Protocol::SendBanner(con.tcpSd);

    try {
    hsOpt = new HandshakeOptionT;
    } 
    catch(const std::bad_alloc) {
      Log::Fatal("Out of memory");
    }

    /* Tcp SSL stuff */

    if ((con.tcpSSL = SSL_new(Network::Server::TcpSSLCtx)) == NULL) {
      Log::Fatal("Cannot create new Tcp SSL");
      goto deleteTcpSd;
    }

    SSL_set_fd(con.tcpSSL, con.tcpSd);

    Log::Debug2("Tcp SSL Handshake");
    if (SSL_accept(con.tcpSSL) <= 0) {
      Log::Error("Cannot complete Tcp SSL handshake");
      goto deleteTcpSSL;
    }

    /* Udp SSL stuff */

    if((con.udpSSL = SSL_new(Network::Server::UdpSSLCtx)) == NULL) {
      Log::Fatal("Cannot create new Udp SSL");
    }

    /* We use the listenUdpHandshakeSock only for the ssl handshake */
    udpBio = BIO_new_dgram(listenUdpHandshakeSock, BIO_NOCLOSE);
    SSL_set_bio(con.udpSSL,udpBio,udpBio);
    SSL_set_accept_state(con.udpSSL);

    Log::Debug2("Udp SSL Handshake");
    if(SSL_do_handshake(con.udpSSL) <= 0) {
      Log::Error("Cannot complete Udp SSL handshake");
      goto deleteTcpSd;
    }

    /* Then we switch to the udpDataSock, which is listening on a different port */
    /* First read remote peer udp port */
    SSL_read(con.tcpSSL,(void *) &remotePort,2);

    /* Then clone the peer struct sockaddr */
    BIO_dgram_get_peer(udpBio,&peer);

    /* Change the port to the current remote peer udp port */ 
    peer.sin_port = remotePort;

    /* Create a new BIO dgram */
    udpBio = BIO_new_dgram(udpDataSock, BIO_NOCLOSE);

    /* And set remote peer */
    BIO_dgram_set_peer(udpBio,&peer);
    memBio = BIO_new(BIO_s_mem());
    
    /* Finish with the exchange */
    SSL_set_bio(con.udpSSL,memBio,udpBio);

    if (!Protocol::Server::Handshake(con.tcpSSL, hsOpt)) {
      Log::Error("Cannot complete lulzVPN handshake");
      goto deleteTcpSSL;
    }

    pthread_mutex_lock(&Peers::db_mutex);
    
    try {
      newPeer = new Peers::Peer(con, hsOpt->peer_username, peer.sin_addr.s_addr, hsOpt->remoteNets, hsOpt->listeningStatus, accepted);
    } 
    catch(const std::bad_alloc) {
      Log::Fatal("Out of memory");
    }

    Peers::Register(newPeer);

    inet_ntop(AF_INET, &peer.sin_addr.s_addr, peerAddress, addressLenght);
    Log::Info("Connection accepted from %s (sd %d)", peerAddress, con.tcpSd);

    /* Set routing */
    Log::Debug2("Setting Routing");
    Taps::setSystemRouting(newPeer, hsOpt->allowedNets, addRouting);

    pthread_mutex_unlock(&Peers::db_mutex);

    pthread_create(&connectQueueT, NULL, CheckConnectionsQueue, &hsOpt->userLs);
    pthread_join(connectQueueT, NULL);
    UpdateNonListeningPeer(newPeer->user(), newPeer->address());
    continue;

deleteTcpSSL:
    SSL_free(con.tcpSSL);
deleteTcpSd:
    close(con.tcpSd);
    delete hsOpt;
  }
  return NULL;
}

void  
Network::Server::UdpRecverInit ()
{

  struct sockaddr_in udpServer;
  socklen_t addrSize;

  addrSize = sizeof(udpServer);

  udpServer.sin_family = AF_INET;
  udpServer.sin_port = htons(Options.BindingPort() + 2);
  udpServer.sin_addr.s_addr = INADDR_ANY;   //(udpServer.opt->binding_address); 
  memset(&(udpServer.sin_zero), '\0', 8);

  if((udpDataSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
     Log::Fatal("cannot create udp socket");
  Log::Debug2("udpDataSock (sd %d) created", udpDataSock);

  Log::Debug2("Binding udp port %d (data channel)", Options.BindingPort());
  if (bind(udpDataSock,(struct sockaddr *) &udpServer, addrSize)==-1)
    Log::Fatal("cannot binding to socket");

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

void *
Network::Client::PeerConnectThreadWrapper (void *stuff) {

     PeerAddrPort *host = (PeerAddrPort *) stuff;
     PeerConnect(host->address, host->port);
     return NULL;
}

void
Network::Client::PeerConnect (int address, short port)
{

  struct sockaddr_in tcpPeer;
  struct sockaddr_in udpPeer;
  struct sockaddr_in localPeer;
  Peers::Connection con;
  HandshakeOptionT hsOpt;
  int udpHandshakeSock;
  BIO *udpBio;
  const uChar invalidId = 0xff;

  pthread_t connectQueueT;
  Peers::Peer * newPeer;
  socklen_t addrLen;

  addrLen = sizeof(struct sockaddr_in);

  tcpPeer.sin_family = AF_INET;
  tcpPeer.sin_port = htons(port);
  tcpPeer.sin_addr.s_addr = address;
  memset(&(tcpPeer.sin_zero), '\0', 8);

  udpPeer.sin_family = AF_INET;
  udpPeer.sin_port = htons(port);
  udpPeer.sin_addr.s_addr = address;
  memset(&(udpPeer.sin_zero), '\0', 8);

  if ((con.tcpSd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    Log::Error("cannot create socket", 1);
    return;
  }

  if (connect(con.tcpSd, (struct sockaddr *) &tcpPeer, sizeof(tcpPeer)) == -1) {
    Log::Error("Cannot connect", 1);
    return;
  }

  Protocol::RecvBanner(con.tcpSd);
  if ((con.tcpSSL = SSL_new(Network::Client::TcpSSLCtx)) == NULL) {
    Log::Fatal("Cannot create new Tcp SSL");
    goto deleteTcpSd;
  }

  SSL_set_fd(con.tcpSSL, con.tcpSd);

  Log::Debug2("SSL Handshake");
  if (SSL_connect(con.tcpSSL) <= 0) {
    Log::Fatal("Cannot complete SSL handshake");
    goto deleteTcpSSL;
  }

  if (!Network::VerifySslCert(con.tcpSSL)) {
    Log::Fatal("Cannot verify SSL certificate");
    goto deleteTcpSSL;
  }

  if((udpHandshakeSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
     Log::Fatal("cannot create udp socket");
     return;
  }

  if((con.udpSSL = SSL_new(Network::Client::UdpSSLCtx)) == NULL) {
    Log::Fatal("Cannot create new Udp SSL");
    goto deleteTcpSSL;
  }

  SSL_set_verify(con.udpSSL, SSL_VERIFY_NONE, NULL);

  udpBio = BIO_new_dgram(udpHandshakeSock, BIO_NOCLOSE);
  BIO_ctrl_dgram_connect(udpBio, &udpPeer);

  SSL_set_bio(con.udpSSL,udpBio,udpBio);
  SSL_set_connect_state(con.udpSSL);

  Log::Debug2("Udp SSL Handshake");
  if(SSL_do_handshake(con.udpSSL) <= 0) {
    Log::Fatal("Cannot complete Udp SSL handshake");
    goto deleteTcpSd;
  }

  if((con.udpSd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
     Log::Fatal("cannot create udp socket");
     return;
  }

  udpPeer.sin_port = htons(port + 2);
  udpBio = BIO_new_dgram(con.udpSd, BIO_NOCLOSE);
  BIO_ctrl_dgram_connect(udpBio, &udpPeer);
  connect(con.udpSd,(struct sockaddr *)&udpPeer,sizeof(udpPeer));
  getsockname(con.udpSd,(struct sockaddr *) &localPeer, &addrLen);
  SSL_write(con.tcpSSL,&localPeer.sin_port,2);

  SSL_set_bio(con.udpSSL,udpBio,udpBio);

  /* Now I send a non sane packet (with an invalid remote id)
   * just to initialize the router connection in case you are 
   * behind nat
   */
  SSL_write(con.udpSSL,&invalidId,1);
  
  if (!Protocol::Client::Handshake(con.tcpSSL, &hsOpt)) {
      Log::Error("Cannot complete lulzVPN handshake");
      goto deleteTcpSSL;
  }

  pthread_mutex_lock(&Peers::db_mutex);
  try{
    newPeer = new Peers::Peer(con, hsOpt.peer_username, address, hsOpt.remoteNets, true, connected);
  } catch(const std::bad_alloc){
    Log::Fatal("Out of memory");
  }

  Peers::Register(newPeer);
  Log::Info("Connected");

  Log::Debug2("Setting Routing");
  Taps::setSystemRouting(newPeer, hsOpt.allowedNets, addRouting);

  pthread_mutex_unlock(&Peers::db_mutex);

  pthread_create(&connectQueueT, NULL, Network::CheckConnectionsQueue, &hsOpt.userLs);
  pthread_join(connectQueueT, NULL);

  return;

deleteTcpSSL:
   SSL_free(con.tcpSSL);
deleteTcpSd:
   close(con.tcpSd);

   return;
}

void
Network::HandleClosingConnection(Peers::Peer *peer, int *flag)
{
  Log::Debug3("control_packet: closing connection");
  peer->setClosing();
  *flag = true;
}

void
Network::HandleNewPeerNotify(Packet::CtrlPacket *packet)
{
  std::vector<Peers::Peer *>::iterator peerIt, peerEnd;
  char user[MAX_USERNAME_LEN + 1];
  uInt address;
  pthread_t connectT;
  PeerAddrPort *host;

  sscanf((char *) packet->buffer + 1, "%s ", user);
  memcpy((char *) &address, (char *) packet->buffer + 1 + strlen(user) + 1, 4);

  peerEnd = Peers::db.end();
  for (peerIt = Peers::db.begin(); peerIt < peerEnd; ++peerIt) {
    if(!(*peerIt)->user().compare(user)){
      Log::Debug2("User alredy connected");
      return;
    }
  }

  host = new PeerAddrPort;
  host->address = address;
  host->port = port;
  pthread_create(&connectT,NULL,Network::Client::PeerConnectThreadWrapper,host);
  
}

void
Network::ForwardToTap (Packet::DataPacket *packet, Peers::Peer *src)
{

  uChar i;
  std::vector<networkT>::const_iterator netIt, netEnd;
  int nAddr;
  Taps::Tap *tap;

  nAddr = Packet::GetDestinationIp(packet);
  i = packet->buffer[0];

  if(i >= Taps::db.size())
       return;

  tap = Taps::db[i];

  if (tap->isActive() && tap->isRoutableAddress(nAddr)) {
    netEnd = src->nl().end();
    for (netIt = src->nl().begin(); netIt < netEnd; ++netIt) {
      if ((*netIt).localId == i) {
        *tap << packet;
        break;
      }
    }
  }
  Log::Dump(packet->buffer, packet->length);
}

void
Network::ForwardToPeer (Packet::DataPacket *packet, uChar localId)
{

  std::vector<Peers::Peer *>::iterator peerIt, peerEnd;
  std::vector<networkT>::const_iterator netIt, netEnd;
  int nAddr;

  nAddr = Packet::GetDestinationIp(packet);
  packet->buffer[0] = localId;

  peerEnd = Peers::db.end();
  for (peerIt = Peers::db.begin(); peerIt < peerEnd; ++peerIt) {
    if ((*peerIt)->isActive() && (*peerIt)->isRoutableAddress(nAddr)) {
      netEnd = (*peerIt)->nl().end();
      for (netIt = (*peerIt)->nl().begin(); netIt < netEnd; ++netIt) {
        if ((*netIt).localId == localId) {
          **peerIt << packet;
          break;
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
    std::cout << "Do you want to continue? [y|n]:";
    std::cin >> answer;

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

void
Network::UpdateNonListeningPeer(std::string user, int address)
{

  std::vector<Peers::Peer *>::iterator peerIt, peerEnd;
  Packet::CtrlPacket *packet;

  peerEnd = Peers::db.end();
  for (peerIt = Peers::db.begin(); peerIt < peerEnd; ++peerIt) {
    if(!(*peerIt)->isListening()){
      if((*peerIt)->user().compare(user)) {
        packet = Packet::BuildNewPeerNotifyPacket(user, address);
	(**peerIt) << packet;
	delete packet;
      }
    }
  }
} 

