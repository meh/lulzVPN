/*
 * "protocol.cpp" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
 *
 * LulzNet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * LulzNet is distributed in the hope that it will be useful,
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
#include <lulznet/tap.h>
#include <lulznet/protocol.h>
#include <lulznet/xfunc.h>

void
Protocol::SendBanner (int fd)
{
  char banner[512];
  int len;

  sprintf(banner, "LulzNet. Version %s", PACKAGE_VERSION);
  len = strlen(banner);
  write(fd, banner, len);
}

void
Protocol::RecvBanner (int fd)
{
  char banner[512];
  int len;

  len = read(fd, banner, 511);
  banner[len] = '\x00';
  Log::Info("Recv Banner:\n%s", banner);

}

bool
Protocol::Server::Handshake (SSL * ssl, HandshakeOptionT * hsOpt)
{

  /*
   * PROTOCOL!1!1ONE
   */

  /* Exchange peer username */
  Log::Debug2("User Exchange");
  if (!LulzNetUserExchange(ssl, hsOpt))
    return FAIL;

  /* Recv hash and do authentication */
  Log::Debug2("Authentication");
  if (!LulzNetAuth(ssl, hsOpt))
    return FAIL;

  hsOpt->allowedNets = Taps::getUserAllowedNetworks(hsOpt->peer_username);

  Log::Debug2("Recving listening status");
  if (!xSSL_read(ssl, &hsOpt->listeningStatus, sizeof(char), "listening status"))
    return FAIL;

  /* Networks exchange */
  Log::Debug2("Recving Networks");
  if (!LulzNetReciveNetworks(ssl, hsOpt))
    return FAIL;

  Log::Debug2("Sending Networks");
  if (!LulzNetSendNetworks(ssl, hsOpt))
    return FAIL;

  /* User exchange */
  Log::Debug2("Recving User list");
  if (!LulzNetReciveUserlist(ssl, hsOpt))
    return FAIL;


  Log::Debug2("Sending User list");
  if (!LulzNetSendUserlist(ssl))
    return FAIL;

  return DONE;
}

bool
Protocol::Client::Handshake (SSL * ssl, HandshakeOptionT * hsOpt)
{
  char listeningStatus;

  /*
   * PROTOCOL!1!!ONE
   */

  Log::Debug2("User Exchange");
  if (!LulzNetUserExchange(ssl, hsOpt))
    return FAIL;

  Log::Debug2("Authentication");
  if (!LulzNetAuth(ssl))
    return FAIL;

  hsOpt->allowedNets = Taps::getUserAllowedNetworks(hsOpt->peer_username);

  /*
   * Handshake
   */

  /* Peer tells remote peer if it's listening or not */
  Log::Debug2("Sending listening status");
  if (Options.Flags() & listeningMode)
    listeningStatus = 1;
  else
    listeningStatus = 0;

  if (!xSSL_write(ssl, &listeningStatus, sizeof(char), "listening status"))
    return FAIL;

  /* Networks exchange */
  Log::Debug2("Sending Networks");
  if (!LulzNetSendNetworks(ssl, hsOpt))
    return FAIL;

  Log::Debug2("Recving Networks");
  if (!LulzNetReciveNetworks(ssl, hsOpt))
    return FAIL;

  /* User exchange */
  Log::Debug2("Recving User list");
  if (!LulzNetSendUserlist(ssl))
    return FAIL;

  Log::Debug2("Sending User list");
  if (!LulzNetReciveUserlist(ssl, hsOpt))
    return FAIL;

  return DONE;
}

bool
Protocol::Server::LulzNetUserExchange (SSL * ssl, HandshakeOptionT * hsOpt)
{
  int rdLen;
  char username[MAX_USERNAME_LEN + 1];
  char userCheck;

  Log::Debug2("Recving username");
  if (!(rdLen = xSSL_read(ssl, username, MAX_USERNAME_LEN, "username")))
    return FAIL;

  username[rdLen] = '\x00';
  hsOpt->peer_username.assign(username);

  Log::Debug2("Sending user check");
  if (Peers::UserIsConnected((char *) hsOpt->peer_username.c_str())) {
    Log::Error("User is connected");
    userCheck = userConnected;
    xSSL_write(ssl, &userCheck, 1, "user info");
    return FAIL;
  }

  if ((!hsOpt->peer_username.compare(Options.Username()))) {
    Log::Error("User is connected (same as local peer)");
    userCheck = userConnected;
    xSSL_write(ssl, &userCheck, 1, "user info");
    return FAIL;
  }

  userCheck = userNotConnected;
  if (!xSSL_write(ssl, &userCheck, 1, "user info"))
    return FAIL;

  /* And send its username */
  Log::Debug2("Sending username");
  if (!xSSL_write(ssl, (void *) Options.Username().c_str(), Options.Username().length(), "username"))
    return FAIL;

  return DONE;
}

bool
Protocol::Client::LulzNetUserExchange (SSL * ssl, HandshakeOptionT * hsOpt)
{
  int rdLen;
  char username[MAX_USERNAME_LEN + 1];
  char userCheck;

  /* Peer send its username */

  Log::Debug2("Sending username");
  if (!xSSL_write(ssl, (char *) Options.Username().c_str(), Options.Username().length(), "username"))
    return FAIL;

  xSSL_read(ssl, &userCheck, 1, "user info");
  if (userCheck == userConnected) {
    Log::Error("user is connected");
    return FAIL;
  }

  /* And recv remote peer username */
  Log::Debug2("Recving username");
  if (!(rdLen = xSSL_read(ssl, username, MAX_USERNAME_LEN, "username")))
    return FAIL;

  username[rdLen] = '\x00';
  hsOpt->peer_username.assign(username);

  return DONE;
}

bool
Protocol::Server::LulzNetAuth (SSL * ssl, HandshakeOptionT * hsOpt)
{

  uChar hex_hash[16];
  char auth;

  /* Recv hash */

  Log::Debug2("Recving hash");
  if (!xSSL_read(ssl, hex_hash, 16, "hash"))
    return FAIL;

  /* Do authentication checking if hash match local credential file's hash */
  if (Auth::DoAuthentication(hsOpt->peer_username, hex_hash)) {
    auth = AUTHENTICATION_SUCCESSFULL;

    Log::Debug2("Sending auth response (successfull)");
    if (!xSSL_write(ssl, &auth, sizeof(char), "auth response"))
      return FAIL;
  }
  else {
    auth = AUTHENTICATION_FAILED;

    Log::Debug2("Sending auth response (failed)");
    xSSL_write(ssl, &auth, sizeof(char), "auth response");
    return FAIL;
  }

  return DONE;
}

bool
Protocol::Client::LulzNetAuth (SSL * ssl)
{

  uChar *hex_hash;
  char auth;

  hex_hash = Auth::Crypt::CalculateMd5(Options.Password());

  /* Then send password's hash */
  Log::Debug2("Sending hash");
  if (!xSSL_write(ssl, hex_hash, 16, "hash")) {
    delete hex_hash;
    return FAIL;
  }

  delete[] hex_hash;

  /* And recv authentication response */

  Log::Debug2("Recving auth response");
  if (!xSSL_read(ssl, &auth, sizeof(char), "auth response"))
    return FAIL;

  Log::Debug2("Server response: %s (%x)", (auth ? "auth successfull" : "auth failed"), auth);
  if (auth == AUTHENTICATION_FAILED) {
    Log::Error("Authentication failed");
    return FAIL;
  }
  return DONE;
}

bool
Protocol::LulzNetSendNetwork (SSL *ssl, networkT net)
{
  int answer;

  Log::Debug2("Sending network name");
  if (!xSSL_write(ssl, (char *) net.networkName.c_str(), net.networkName.length(), "network name"))
    return FAIL;

  Log::Debug2("Sending network id");
  if (!xSSL_write(ssl, &net.remoteId, sizeof(uChar), "address id"))
    return FAIL;

  Log::Debug2("Sending address");
  if (!xSSL_write(ssl, &net.address, sizeof(int), "address list"))
    return FAIL;

  Log::Debug2("Sending netmask");
  if (!xSSL_write(ssl, &net.netmask, sizeof(int), "netmask list"))
    return FAIL;

  Log::Debug2("Recving net conflict answer");
  if (!xSSL_read(ssl, &answer, sizeof(int), "net conflict check"))
    return FAIL;

  if (answer == networkNotAllowed) {
    Log::Error("Network %s is not allowed on remote peer", net.networkName.c_str());
    return FAIL;
  }

    return DONE;
}

bool
Protocol::LulzNetRecvNetwork (SSL *ssl, networkT *net, std::vector<networkT> allowedNets)
{
  int answer;
  int rdLen;
  char netName[MAX_NETWORKNAME_LEN + 1];
  std::vector<networkT>::iterator netIt, netEnd;

  if (!(rdLen = xSSL_read(ssl, netName, MAX_NETWORKNAME_LEN, "network name")))
    return FAIL;

  netName[rdLen] = '\x00';
  net->networkName = netName;

  if (!(rdLen = xSSL_read(ssl, &net->remoteId, sizeof(uChar), "network id")))
    return FAIL;

  if (!(rdLen = xSSL_read(ssl, &net->address, sizeof(int), "address")))
    return FAIL;

  if (!(rdLen = xSSL_read(ssl, &net->netmask, sizeof(int), "netmask")))
    return FAIL;

  net->network = get_ip_address_network(net->address, net->netmask);

  answer = networkNotAllowed;

  netEnd = allowedNets.end();
  for (netIt = allowedNets.begin(); netIt < netEnd; ++netIt)
    if (!(*netIt).networkName.compare(net->networkName)) {
      answer = networkAllowed;
      break;
    }

  if (!xSSL_write(ssl, &answer, sizeof(int), "net conflict check"))
    return FAIL;

  if (answer == networkNotAllowed)
    return FAIL;

    net->localId = Taps::getNetworkId(net->networkName);
    return DONE;

}

bool
Protocol::LulzNetSendNetworks (SSL * ssl, HandshakeOptionT * hsOpt)
{
  int netCount;
  std::vector<networkT>::iterator netIt, netEnd;

  netCount = hsOpt->allowedNets.size();

  Log::Debug2("Sending available network count");
  if (netCount == 0) {

    Log::Debug2("Peer cannot access any networks");
    xSSL_write(ssl, &netCount, sizeof(int), "network count");
    return FAIL;
  }

  if (!xSSL_write(ssl, &netCount, sizeof(int), "network count"))
    return FAIL;

  netEnd = hsOpt->allowedNets.end();
  for (netIt = hsOpt->allowedNets.begin(); netIt < netEnd; ++netIt)
       if(!LulzNetSendNetwork(ssl, *netIt))
	    return FAIL;

  return DONE;

}

bool
Protocol::LulzNetReciveNetworks (SSL * ssl, HandshakeOptionT * hsOpt)
{
  int i;
  int rdLen;
  int netCount;
  networkT net;

  Log::Debug2("Recving available network count");
  if (!(rdLen = xSSL_read(ssl, &netCount, sizeof(int), "network count")))
    return FAIL;

  if (netCount == 0) {
    Log::Error("No network available");
    return FAIL;
  }

  for (i = 0; i < netCount; i++)
    if(!LulzNetRecvNetwork(ssl, &net, hsOpt->allowedNets))
      return FAIL;
    else
      hsOpt->remoteNets.push_back(net);

  return DONE;
}

bool
Protocol::LulzNetSendUser (SSL *ssl, userT user)
{
  if (!xSSL_write(ssl, (char *) user.user.c_str(), user.user.length(), "user"))
    return FAIL;
  if (!xSSL_write(ssl, &user.address, sizeof(int), "address"))
    return FAIL;

  return DONE;
}

bool
Protocol::LulzNetRecvUser (SSL *ssl, userT *user) {

  int rdLen;
  char username[MAX_USERNAME_LEN + 1];

  if (!(rdLen = xSSL_read(ssl, username, MAX_USERNAME_LEN, "user")))
    return FAIL;

  username[rdLen] = '\x00';
  user->user = username;

  if (!(rdLen = xSSL_read(ssl, &user->address, sizeof(int), "address")))
    return FAIL;

  return DONE;
}

bool
Protocol::LulzNetSendUserlist (SSL * ssl)
{
  int userCount;
  std::vector<userT> userLs;
  std::vector<userT>::iterator userIt, userEnd;

  userLs = Protocol::GetUserlist();
  userCount = userLs.size();

  Log::Debug2("Sending peer count");
  if (!xSSL_write(ssl, &userCount, sizeof(int), "peer count"))
    return FAIL;

  /* And send peers address */
  userEnd = userLs.end();
  for (userIt = userLs.begin(); userIt < userEnd; ++userIt)
    if(!LulzNetSendUser(ssl, *userIt))
      return FAIL;

  return DONE;
}

bool
Protocol::LulzNetReciveUserlist (SSL * ssl, HandshakeOptionT * hsOpt)
{
  int i;
  int userCount;
  userT user;

  if (!xSSL_read(ssl, &userCount, sizeof(int), "peer count"))
    return FAIL;

  /* And recv peers Log::Info */
  for (i = 0; i < userCount; i++) 
    if(!LulzNetRecvUser(ssl, &user))
      return FAIL;
    else
      hsOpt->userLs.push_back(user);

  return DONE;
}

std::vector<userT>
Protocol::GetUserlist ()
{

  std::vector<userT> userLs;
  std::vector<Peers::Peer *>::iterator peerIt, peerEnd;
  userT user;

  peerEnd = Peers::db.end();
  for (peerIt = Peers::db.begin(); peerIt < peerEnd; ++peerIt) {
    if((*peerIt)->isListening()){
      user.user = (*peerIt)->user();
      user.address = (*peerIt)->address();

      userLs.push_back(user);
    }
  }

  return userLs;
}
