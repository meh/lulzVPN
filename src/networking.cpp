/*
 * "networking.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

#include <lulznet/auth.h>
#include <lulznet/config.h>
#include <lulznet/log.h>
#include <lulznet/networking.h>
#include <lulznet/peer.h>
#include <lulznet/protocol.h>
#include <lulznet/packet.h>
#include <lulznet/tap.h>

SSL_CTX *Network::Client::sslCTX;
SSL_CTX *Network::Server::sslCTX;

fd_set Network::master;
pthread_t Network::Server::select_t;
int Network::freeFdFlag;

void Network::Server::sslInit ()
{
  Network::Server::sslCTX = SSL_CTX_new (SSLv23_server_method ());

  if (!Network::Server::sslCTX)
    Log::Fatal ("Failed to do SSL CTX new");


  Log::Debug2 ("Loading SSL certificate");
  if (SSL_CTX_use_certificate_file
      (Network::Server::sslCTX, CERT_FILE, SSL_FILETYPE_PEM) <= 0)
    Log::Fatal ("Failed to load SSL certificate %s", CERT_FILE);


  Log::Debug2 ("Loading SSL private key");
  if (SSL_CTX_use_PrivateKey_file
      (Network::Server::sslCTX, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
    Log::Fatal ("Failed to load SSL private key %s", KEY_FILE);
}

void Network::Client::sslInit ()
{
  Network::Client::sslCTX = SSL_CTX_new (SSLv23_client_method ());
}

void *Network::Server::ServerLoop (void *arg __attribute__ ((unused)))
{

  int listenSock;
  int peerSock;
  int on = 1;
  SSL *peerSsl;
  char peer_address[ADDRESS_LEN + 1];
  struct sockaddr_in server;
  struct sockaddr_in peer;
  socklen_t addrSize;
  pthread_t connectQueueT;
  HandshakeOptionT *hsOpt;
  Peers::Peer *newPeer;

  if ((listenSock = socket (PF_INET, SOCK_STREAM, 0)) == -1)
    Log::Fatal ("cannot create socket");


  Log::Debug2 ("listenSock (fd %d) created", listenSock);
  if (setsockopt (listenSock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) ==
      -1)
    Log::Error ("setsockopt SO_REUSEADDR: %s", strerror (errno));

  server.sin_family = AF_INET;
  server.sin_port = htons (Options.BindingPort ());
  server.sin_addr.s_addr = INADDR_ANY;	/*(server_opt->binding_address); */
  memset (&(server.sin_zero), '\0', 8);


  Log::Debug2 ("Binding port %d", PORT);
  if (bind
      (listenSock, (struct sockaddr *) &server,
       sizeof (struct sockaddr)) == -1)
    Log::Fatal ("cannot binding to socket");


  Log::Debug1 ("Listening");
  if (listen (listenSock, MAX_ACCEPTED_PEERS_CONNECTIONS) == -1)
    Log::Fatal ("cannot listen");

  addrSize = sizeof (struct sockaddr_in);

  /* @TODO while(available_connection()) else sleep && goto! */
  while (1)
    {
      if ((peerSock =
             accept (listenSock, (struct sockaddr *) &peer, &addrSize)) == -1)
        Log::Fatal ("cannot accept");

      Protocol::SendBanner (peerSock);
      hsOpt = new HandshakeOptionT;

      if ((peerSsl = SSL_new (Network::Server::sslCTX)) != NULL)
        {
          SSL_set_fd (peerSsl, peerSock);

          Log::Debug2 ("SSL Handshake");
          if (SSL_accept (peerSsl) > 0)
            {
              if (Protocol::Server::Handshake (peerSsl, hsOpt))
                {
                  pthread_mutex_lock (&Peers::db_mutex);

                  newPeer = new Peers::Peer (peerSock, peerSsl, hsOpt->peer_username,
                                             peer.sin_addr.s_addr, hsOpt->remoteNets,
                                             INCOMING_CONNECTION);
                  inet_ntop (AF_INET, &peer.sin_addr.s_addr, peer_address,
                             ADDRESS_LEN);
                  Log::Info ("Connection accepted from %s (fd %d)", peer_address,
                             peerSock);

                  /* Set routing */
                  Log::Debug2 ("Setting Routing");
                  Taps::setSystemRouting (newPeer, hsOpt->allowedNets, ADD_ROUTING);

                  pthread_mutex_unlock (&Peers::db_mutex);

                  pthread_create (&connectQueueT, NULL, CheckConnectionsQueue,
                                  &hsOpt->userLs);
                  pthread_join (connectQueueT, NULL);
                  delete hsOpt;
                }
              else
                {
                  Log::Error("Cannot complete handshake");
                  SSL_free (peerSsl);
                  close (peerSock);
                  delete hsOpt;
                }
            }
          else
            {
              Log::Error ("Cannot complete SSL handshake");
              close (peerSock);
              delete hsOpt;
            }
        }
      else
        {

          Log::Error ("Cannot create new SSL");
          close (peerSock);
          delete hsOpt;
        }
    }
  return NULL;
}

int Network::LookupAddress (std::string address)
{

  struct hostent *host_info;


  Log::Debug1 ("Looking up client %s", address.c_str ());
  host_info = gethostbyname (address.c_str ());

  if (host_info == NULL)
    {
      Log::Error ("Cannot lookup hostname", 1);
      return 0;
    }

  return *((int *) host_info->h_addr);

}

void Network::Client::PeerConnect (int address, short port)
{

  struct sockaddr_in peer;
  int peerSock;
  SSL *peerSsl;
  HandshakeOptionT hsOpt;

  pthread_t connectQueueT;
  Peers::Peer * newPeer;

  /* check if is there any free Peer */
  if (Peers::conections_to_peer == MAX_CONNECTIONS_TO_PEER)
    {
      Log::Error ("Exceded max connections to peer");
      return;
    }

  if ((peerSock = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
      Log::Error ("cannot create socket", 1);
      return;
    }


  Log::Debug2 ("peer sock (fd %d) created", peerSock);

  peer.sin_family = AF_INET;
  peer.sin_port = htons (port ? port : PORT);
  peer.sin_addr.s_addr = address;
  memset (&(peer.sin_zero), '\0', 8);

  if (connect (peerSock, (struct sockaddr *) &peer, sizeof (peer)) == -1)
    {
      Log::Error ("Cannot connect", 1);
      return;
    }

  Protocol::RecvBanner (peerSock);

  if ((peerSsl = SSL_new (Network::Client::sslCTX)) != NULL)
    {
      SSL_set_fd (peerSsl, peerSock);

      Log::Debug2 ("SSL Handshake");
      if (SSL_connect (peerSsl) > 0)
        {
          if (Network::VerifySslCert (peerSsl))
            {
              if (Protocol::Client::Handshake (peerSsl, &hsOpt))
                {
                  pthread_mutex_lock (&Peers::db_mutex);

                  newPeer =
                    new Peers::Peer (peerSock, peerSsl, hsOpt.peer_username, address,
                                     hsOpt.remoteNets, OUTGOING_CONNECTION);
                  Log::Info ("Connected");

                  Log::Debug2 ("Setting Routing");
                  Taps::setSystemRouting (newPeer, hsOpt.allowedNets, ADD_ROUTING);

                  pthread_mutex_unlock (&Peers::db_mutex);

                  pthread_create (&connectQueueT, NULL,
                                  Network::CheckConnectionsQueue, &hsOpt.userLs);
                  pthread_join (connectQueueT, NULL);

                }
              else
                {
                  Log::Error ("Cannot complete lulznet handshake");
                  SSL_free (peerSsl);
                  close (peerSock);
                }

            }
          else
            {
              Log::Error ("Cannot verify host identity");
              SSL_free (peerSsl);
              close (peerSock);
            }
        }
      else
        {
          Log::Error ("Cannot complete SSL handshake");
          SSL_free (peerSsl);
          close (peerSock);
        }
    }
  else
    {
      Log::Error ("Cannot creane new SSL");
      close (peerSock);
    }
}

void *Network::Server::SelectLoop (void __attribute__ ((unused)) * arg)
{
  Packet packet;
  int ret;
  fd_set readSelect;
  int maxFd;
  int i;
  Peers::Peer * peer;
  Taps::Tap * tap;

  int dont_close_flag = 1;

  while (dont_close_flag)
    {
      pthread_mutex_lock (&Peers::db_mutex);
      readSelect = Network::master;
      freeFdFlag = 0;
      maxFd = (Peers::maxFd > Taps::maxFd ? Peers::maxFd : Taps::maxFd);
      pthread_mutex_unlock (&Peers::db_mutex);

      ret = select (maxFd + 1, &readSelect, NULL, NULL, NULL);

      pthread_mutex_lock (&Peers::db_mutex);
      if (ret == -1)
        Log::Fatal ("Select Log::Error");
      else
        {
          /* 0,1 and 2 are stdin-out-err and we don't care about them */
          for (i = 0; i < Peers::count; i++)
            {
              peer = Peers::db[i];
              if (peer->isActive () && peer->isReadyToRead(&readSelect))
                {
                  /* Read from it */
                  if ( *peer >> &packet )
                    {
                      switch (packet.buffer[0])
                        {
                        case DATA_PACKET:
                          Network::Server::ForwardToTap (&packet);
                          break;
                        case CONTROL_PACKET:
                          if (packet.buffer[1] == CLOSE_CONNECTION)
                            {

                              Log::Debug3 ("control_packet: closing connection");
                              freeFdFlag = 1;
                              peer->setClosing ();
                            }
                          else
                            Log::Error ("Unknow control flag");
                          break;
                        }
                    }
                  else
                    freeFdFlag = TRUE;
                }
            }
          if (freeFdFlag)
            Peers::FreeNonActive ();

          for (i = 0; i < Taps::count; i++)
            {
              tap = Taps::db[i];
              if (tap->isActive() && tap->isReadyToRead(&readSelect))
                {
                  if (*tap >> &packet)
                    Network::Server::ForwardToPeer (&packet);
                }
            }
        }

      /* When the cycle is end functions can modify the fd_db structure */
      pthread_mutex_unlock (&Peers::db_mutex);
    }
  return NULL;
}

void Network::Server::RestartSelectLoop ()
{

  Log::Debug2 ("Restarting select()");
  if (Network::Server::select_t != (pthread_t) NULL)
    {
      if (pthread_cancel (Network::Server::select_t))
        Log::Fatal ("Cannot cancel select thread");
      else
        pthread_create (&Network::Server::select_t, NULL,
                        Network::Server::SelectLoop, NULL);
    }
}

inline void Network::Server::ForwardToTap (Network::Packet * packet)
{

  int i;
  int nAddr;

  nAddr = PacketInspection::get_destination_ip(packet);

  for (i = 0; i < Taps::count; i++)
    if (Taps::db[i]->isActive())
      if (Taps::db[i]->isRoutableAddress(nAddr))
        *Taps::db[i] << packet;


  Log::Dump (packet->buffer, packet->length);
}

inline void Network::Server::ForwardToPeer (Network::Packet * packet)
{

  int i;
  int nAddr;

  nAddr = PacketInspection::get_destination_ip(packet);
  packet->buffer[0] = DATA_PACKET;

  for (i = 0; i < Peers::count; i++)
    if (Peers::db[i]->isActive())
      if (Peers::db[i]->isRoutableAddress(nAddr))
        *Peers::db[i] << packet;


  Log::Dump (packet->buffer, packet->length);
}

int Network::VerifySslCert (SSL * ssl)
{
  char *fingerprint;
  //char answer;

  if (SSL_get_verify_result (ssl) != X509_V_OK)
    {
      fingerprint = Auth::Crypt::GetFingerprintFromCtx (ssl);
      std::cout << "Could not verify SSL servers certificate (self signed)." << std::endl;
      std::cout << "Fingerprint is: "<< fingerprint << std::endl;
      std::cout << "Do you want to continue? [y|n]: y\n";
      //    std::cin >> answer;

      delete[] fingerprint;

//      if (answer == 'y' || answer == 'Y')
      return TRUE;
//      else
      //      return FALSE;
    }

  return TRUE;
}

void *Network::CheckConnectionsQueue (void *arg)
{

  unsigned int i;
  userListT *userLs;
  userLs = (userListT *) arg;

  if (userLs->user.size() == 0)
    return NULL;

  for (i = 0; i < userLs->user.size(); i++)

    /* check if we're connected to peer */
    if (!Peers::UserIsConnected (userLs->user[i]))
      Network::Client::PeerConnect (userLs->address[i], PORT);

  return NULL;
}
