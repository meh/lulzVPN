/*
 * "protocol.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
 *
 * LulzNet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your hsOption) any later version.
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

void Protocol::SendBanner (int fd)
{
  char banner[512];
  int len;

  sprintf (banner, "LulzNet. Version %s", VERSION);
  len = strlen (banner);
  write (fd, banner, len);
}

void Protocol::RecvBanner (int fd)
{
  char banner[512];
  int len;

  len = read (fd, banner, 511);
  banner[len] = '\x00';
  Log::Info ("Recv Banner:\n%s", banner);

}

int Protocol::Server::Handshake (SSL * ssl, HandshakeOptionT * hsOpt)
{

  char listeningStatus;
  /*
   * PROTOCOL!1!1ONE
   */

  /* Exchange peer username */
  Log::Debug2 ("User Exchange");
  if (!LulzNetUserExchange (ssl, hsOpt))
    return FAIL;

  /* Recv hash and do authentication */
  Log::Debug2 ("Authentication");
  if (!LulzNetAuth (ssl, hsOpt))
    return FAIL;

  hsOpt->allowedNets = Taps::getUserAllowedNetworks(hsOpt->peer_username);

  Log::Debug2 ("Recving listening status");
  if (!xSSL_read (ssl, &listeningStatus, sizeof (char), "listening status"))
    return FAIL;

  /* Networks exchange */
  Log::Debug2 ("Recving Networks");
  if (!LulzNetReciveNetworks (ssl, hsOpt))
    return FAIL;


  Log::Debug2 ("Sending Networks");
  if (!LulzNetSendNetworks (ssl, hsOpt))
    return FAIL;

  /* User exchange */
  Log::Debug2 ("Recving User list");
  if (!LulzNetReciveUserlist (ssl, hsOpt))
    return FAIL;


  Log::Debug2 ("Sending User list");
  if (!LulzNetSendUserlist (ssl))
    return FAIL;

  return DONE;
}

int Protocol::Client::Handshake (SSL * ssl, HandshakeOptionT * hsOpt)
{
  char listeningStatus;

  /*
   * PROTOCOL!1!!ONE
   */

  Log::Debug2 ("User Exchange");
  if (!LulzNetUserExchange (ssl, hsOpt))
    return FAIL;

  Log::Debug2 ("Authentication");
  if (!LulzNetAuth (ssl))
    return FAIL;

  hsOpt->allowedNets = Taps::getUserAllowedNetworks(hsOpt->peer_username);

  /*
   * Hanshake
   */

  /* Peer tells remote peer if it's listening or not */
  /* we need to know this for routing */

  Log::Debug2 ("Sending listening status");
  if (Options.Flags () & LISTENING_MODE)
    listeningStatus = 1;
  else
    listeningStatus = 0;

  if (!xSSL_write (ssl, &listeningStatus, sizeof (char), "listening status"))
    return FAIL;

  /* Networks exchange */
  Log::Debug2 ("Sending Networks");
  if (!LulzNetSendNetworks (ssl, hsOpt))
    return FAIL;

  Log::Debug2 ("Recving Networks");
  if (!LulzNetReciveNetworks (ssl, hsOpt))
    return FAIL;

  /* User exchange */
  Log::Debug2 ("Recving User list");
  if (!LulzNetSendUserlist (ssl))
    return FAIL;

  Log::Debug2 ("Sending User list");
  if (!LulzNetReciveUserlist (ssl, hsOpt))
    return FAIL;

  return DONE;
}

int Protocol::Server::LulzNetUserExchange (SSL * ssl, HandshakeOptionT * hsOpt)
{
  int rdLen;
  char username[MAX_USERNAME_LEN + 1];
  char userCheck;

  Log::Debug2 ("Recving username");
  if (!(rdLen = xSSL_read (ssl, username, MAX_USERNAME_LEN, "username")))
    return FAIL;

  username[rdLen] = '\x00';
  hsOpt->peer_username.assign (username);

  Log::Debug2("Sending user check");
  if (Peers::UserIsConnected ((char *) hsOpt->peer_username.c_str ()))
    {
      Log::Error("User is connected");
      userCheck = USER_CONNECTED;
      xSSL_write (ssl, &userCheck, 1, "user info");
      return FAIL;
    }

  if ((!hsOpt->peer_username.compare (Options.Username ())))
    {
      Log::Error("User is connected (same as local peer)");
      userCheck = USER_CONNECTED;
      xSSL_write (ssl, &userCheck, 1, "user info");
      return FAIL;
    }

  userCheck = USER_NOT_CONNECTED;
  if (!xSSL_write (ssl, &userCheck, 1, "user info"))
    return FAIL;

  /* And send its username */
  Log::Debug2 ("Sending username");
  if (!xSSL_write (ssl, (void *) Options.Username ().c_str (), Options.Username ().length (), "username"))
    return FAIL;

  return DONE;
}

int Protocol::Client::LulzNetUserExchange (SSL * ssl, HandshakeOptionT * hsOpt)
{
  int rdLen;
  char username[MAX_USERNAME_LEN + 1];
  char userCheck;

  /* Peer send its username */

  Log::Debug2 ("Sending username");
  if (!xSSL_write(ssl, (char *) Options.Username ().c_str (), Options.Username ().length (), "username"))
    return FAIL;

  xSSL_read (ssl, &userCheck, 1, "user info");
  if (userCheck == USER_CONNECTED)
    {
      Log::Error ("user is connected");
      return FAIL;
    }

  /* And recv remote peer username */
  Log::Debug2 ("Recving username");
  if (!(rdLen = xSSL_read (ssl, username, MAX_USERNAME_LEN, "username")))
    return FAIL;

  username[rdLen] = '\x00';
  hsOpt->peer_username.assign (username);

  return DONE;
}

int Protocol::Server::LulzNetAuth (SSL * ssl, HandshakeOptionT * hsOpt)
{

  uChar hex_hash[16];
  char auth;

  /* Recv hash */

  Log::Debug2 ("Recving hash");
  if (!xSSL_read (ssl, hex_hash, 16, "hash"))
    return FAIL;

  /* Do authentication checking if hash match local credential file's hash */
  if (Auth::DoAuthentication (hsOpt->peer_username, hex_hash))
    {
      auth = AUTHENTICATION_SUCCESSFULL;

      Log::Debug2 ("Sending auth response (successfull)");
      if (!xSSL_write (ssl, &auth, sizeof (char), "auth response"))
        return FAIL;
    }
  else
    {
      auth = AUTHENTICATION_FAILED;

      Log::Debug2 ("Sending auth response (failed)");
      xSSL_write (ssl, &auth, sizeof (char), "auth response");
      return FAIL;
    }

  return DONE;
}

int Protocol::Client::LulzNetAuth (SSL * ssl)
{

  uChar *hex_hash;
  char auth;

  hex_hash = Auth::Crypt::CalculateMd5 (Options.Password());

  /* Then send password's hash */
  Log::Debug2 ("Sending hash");
  if (!xSSL_write (ssl, hex_hash, 16, "hash"))
    {
      delete hex_hash;
      return FAIL;
    }

  delete[] hex_hash;

  /* And recv authentication response */

  Log::Debug2 ("Recving auth response");
  if (!xSSL_read (ssl, &auth, sizeof (char), "auth response"))
    return FAIL;

  Log::Debug2 ("Server response: %s (%x)",(auth ? "auth successfull" : "auth failed"), auth);
  if (auth == AUTHENTICATION_FAILED)
    {
      Log::Error ("Authentication failed");
      return FAIL;
    }
  return DONE;
}

/*TODO: add control to check if network exists on remote peer */
int Protocol::LulzNetSendNetworks (SSL * ssl, HandshakeOptionT * hsOpt)
{
  int i;
  int answer;
  int netCount;

  netCount = hsOpt->allowedNets.NetworkName.size();

  Log::Debug2 ("Sending available network count");
  if (netCount == 0)
    {

      Log::Debug2 ("Peer cannot access any networks");
      xSSL_write (ssl, &netCount, sizeof (int), "network count");
      return FAIL;
    }

  if (!xSSL_write (ssl, &netCount, sizeof (int), "network count"))
    return FAIL;

  /* TODO: add max remote peer capabilities */
  for (i = 0; i < netCount; i++)
    {

      Log::Debug2 ("Sending network name");
      if (!xSSL_write (ssl, (char *) hsOpt->allowedNets.NetworkName[i].c_str(), hsOpt->allowedNets.NetworkName[i].length(), "network name"))
        return FAIL;

      Log::Debug2 ("Sending address");
      if (!xSSL_write
          (ssl, &hsOpt->allowedNets.address[i], sizeof (int), "address list"))
        return FAIL;

      Log::Debug2 ("Sending netmask");
      if (!xSSL_write
          (ssl, &hsOpt->allowedNets.netmask[i], sizeof (int), "netmask list"))
        return FAIL;

      Log::Debug2 ("Recving net conflict answer");
      if (!xSSL_read(ssl, &answer, sizeof(int), "net conflict check"))
        return FAIL;

      if (answer == NETWORK_NOT_ALLOWED)
        {
          Log::Error ("Network %s is not allowed on remote peer",hsOpt->allowedNets.NetworkName[i].c_str());
          return FAIL;
        }
    }

  return DONE;

}

int Protocol::LulzNetReciveNetworks (SSL * ssl, HandshakeOptionT * hsOpt)
{
  int i;
  unsigned int j;
  int rdLen;
  int netCount;
  char networkName[MAX_NETWORKNAME_LEN + 1];
  int address;
  int netmask;
  int answer;

  Log::Debug2 ("Recving available network count");
  if (!(rdLen = xSSL_read (ssl, &netCount, sizeof (int), "network count")))
    return FAIL;

  if (netCount == 0)
    {
      Log::Error ("No network available");
      return FAIL;
    }

  for (i = 0; i < netCount && i < MAX_TAPS; i++)
    {
      if (!(rdLen = xSSL_read (ssl, networkName, MAX_NETWORKNAME_LEN, "network name")))
        return FAIL;

      networkName[rdLen] = '\x00';
      hsOpt->remoteNets.NetworkName.push_back(networkName);

      if (!(rdLen = xSSL_read (ssl, &address, sizeof (int), "address")))
        return FAIL;

      hsOpt->remoteNets.address.push_back(address);

      if (!(rdLen = xSSL_read (ssl, &netmask, sizeof (int), "netmask")))
        return FAIL;

      hsOpt->remoteNets.netmask.push_back(netmask);

      hsOpt->remoteNets.network.push_back(get_ip_address_network(address, netmask));

      answer = NETWORK_NOT_ALLOWED;

      for (j = 0; j < hsOpt->allowedNets.NetworkName.size(); j++)
        if (!hsOpt->allowedNets.NetworkName[j].compare(hsOpt->remoteNets.NetworkName.back()))
          {
            answer = NETWORK_ALLOWED;
            break;
          }

      if (!xSSL_write(ssl, &answer, sizeof(int), "net conflict check"))
        return FAIL;

      if (answer == NETWORK_NOT_ALLOWED)
        return FAIL;
    }

  return DONE;
}

int Protocol::LulzNetSendUserlist (SSL * ssl)
{
  int i;
  int userCount;
  userListT userLs;

  userLs = Protocol::GetUserlist ();
  userCount = userLs.user.size();


  Log::Debug2 ("Sending peer count");
  if (!xSSL_write (ssl, &userCount, sizeof (int), "peer count"))
    return FAIL;

  /* And send peers address */
  for (i = 0; i < userCount; i++)
    {
      if (!xSSL_write (ssl, (char *) userLs.user[i].c_str(), userLs.user[i].length(), "user"))
        return FAIL;
      if (!xSSL_write
          (ssl, &userLs.address[i], sizeof (int), "address"))
        return FAIL;
    }
  return DONE;
}

int Protocol::LulzNetReciveUserlist (SSL * ssl, HandshakeOptionT * hsOpt)
{
  int i;
  int rdLen;
  int userCount;
  char username[MAX_USERNAME_LEN + 1];
  int address;

  if (!xSSL_read (ssl, &userCount, sizeof (int), "peer count"))
    return FAIL;

  /* And recv peers Log::Info */
  for (i = 0; i < userCount && i < MAX_PEERS; i++)
    {
      if (!(rdLen = xSSL_read (ssl, username, MAX_USERNAME_LEN, "user")))
        return FAIL;

      username[rdLen] = '\x00';
      hsOpt->userLs.user.push_back(username);

      if (!(rdLen = xSSL_read (ssl, &address, sizeof (int), "address")))
        return FAIL;

      hsOpt->userLs.address.push_back(address);
    }
  return DONE;
}

userListT Protocol::GetUserlist ()
{

  int i;
  Peers::Peer * peer;

  userListT userLs;

  for (i = 0; i < Peers::count; i++)
    {
      peer = Peers::db[i];

      userLs.user.push_back(peer->user ());
      userLs.address.push_back(peer->address ());
    }

  return userLs;
}

