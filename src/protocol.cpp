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

/* Global var used to store packets send
 * and recv during handshake
 * TODO: find right size
 */
char packet[64];

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
  /*
   * PROTOCOL!1!1ONE
   */

  /* Exchange peer username */
  if (!LulzNetUserExchange (ssl, hsOpt))
    return FAIL;

  /* Recv hash and do authentication */
  if (!LulzNetAuth (ssl, hsOpt))
    return FAIL;

  hsOpt->allowedNets = Taps::getUserAllowedNetworks(hsOpt->peer_username);

#ifdef DEBUG
  Log::Debug2 ("Recving listening status");
#endif
  if (!xSSL_read (ssl, packet, sizeof (char), "listening status"))
    return FAIL;

  /* Networks exchange */
  if (!LulzNetReciveNetworks (ssl, hsOpt))
    return FAIL;

  if (!LulzNetSendNetworks (ssl, hsOpt))
    return FAIL;

  /* User exchange */
  if (!LulzNetReciveUserlist (ssl, hsOpt))
    return FAIL;

  if (!LulzNetSendUserlist (ssl))
    return FAIL;

  return DONE;
}

int Protocol::Client::Handshake (SSL * ssl, HandshakeOptionT * hsOpt)
{

  /*
   * PROTOCOL!1!!ONE
   */

  if (!LulzNetUserExchange (ssl, hsOpt))
    return FAIL;

  if (!LulzNetAuth (ssl))
    return FAIL;

  hsOpt->allowedNets = Taps::getUserAllowedNetworks(hsOpt->peer_username);

  /*
   * Hanshake
   */

  /* Peer tells remote peer if it's listening or not */
  /* we need to know this for routing */
#ifdef DEBUG
  Log::Debug2 ("Sending listening status");
#endif
  if (Options.Flags () & LISTENING_MODE)
    packet[0] = 1;
  else
    packet[0] = 0;

  if (!xSSL_write (ssl, packet, sizeof (char), "listening status"))
    return FAIL;

  /* Networks exchange */
  if (!LulzNetSendNetworks (ssl, hsOpt))
    return FAIL;

  if (!LulzNetReciveNetworks (ssl, hsOpt))
    return FAIL;

  /* User exchange */
  if (!LulzNetSendUserlist (ssl))
    return FAIL;

  if (!LulzNetReciveUserlist (ssl, hsOpt))
    return FAIL;

  return DONE;
}

int Protocol::Server::LulzNetUserExchange (SSL * ssl, HandshakeOptionT * hsOpt)
{
  int rdLen;

#ifdef DEBUG
  Log::Debug2 ("Recving username");
#endif
  if (!(rdLen = xSSL_read (ssl, packet, MAX_USERNAME_LEN, "username")))
    return FAIL;

  packet[rdLen] = '\x00';
  hsOpt->peer_username.assign (packet);

  if (Peers::UserIsConnected ((char *) hsOpt->peer_username.c_str ()))
    {
      Log::Error("User is connected");
      packet[0] = 0;
      xSSL_write (ssl, packet, 1, "user info");
      return FAIL;
    }

  if ((!hsOpt->peer_username.compare (Options.Username ())))
    {
      Log::Error("User is connected (same as local peer)");
      packet[0] = 0;
      xSSL_write (ssl, packet, 1, "user info");
      return FAIL;
    }

  packet[0] = 1;
  if (!xSSL_write (ssl, packet, 1, "user info"))
    return FAIL;

  /* And send its username */
#ifdef DEBUG
  Log::Debug2 ("Sending username");
#endif
  if (!xSSL_write
      (ssl, (void *) Options.Username ().c_str (),
       Options.Username ().length (), "username"))
    return FAIL;

  return DONE;
}

int Protocol::Client::LulzNetUserExchange (SSL * ssl, HandshakeOptionT * hsOpt)
{
  int rdLen;

  /* Peer send its username */
#ifdef DEBUG
  Log::Debug2 ("Sending username");
#endif
  if (!xSSL_write
      (ssl, (char *) Options.Username ().c_str (),
       Options.Username ().length (), "username"))
    return FAIL;

  xSSL_read (ssl, packet, 1, "user info");
  if (packet[0] == 0)
    {
      Log::Error ("user is connected");
      return FAIL;
    }

  /* And recv remote peer username */
#ifdef DEBUG
  Log::Debug2 ("Recving username");
#endif
  if (!(rdLen = xSSL_read (ssl, packet, MAX_USERNAME_LEN, "username")))
    return FAIL;
  packet[rdLen] = '\x00';
  hsOpt->peer_username.assign (packet);

  return DONE;
}

int Protocol::Server::LulzNetAuth (SSL * ssl, HandshakeOptionT * hsOpt)
{

  uChar hex_hash[16];
  char auth;

  /* Recv hash */
#ifdef DEBUG
  Log::Debug2 ("Recving hash");
#endif
  if (!xSSL_read (ssl, hex_hash, 16, "hash"))
    return FAIL;

  /* Do authentication checking if hash match local credential file's hash */
  if (Auth::DoAuthentication (hsOpt->peer_username, hex_hash))
    {
      auth = AUTHENTICATION_SUCCESSFULL;
#ifdef DEBUG
      Log::Debug2 ("Sending auth response (successfull)");
#endif
      if (!xSSL_write (ssl, &auth, sizeof (char), "auth response"))
        return FAIL;
    }
  else
    {
      auth = AUTHENTICATION_FAILED;
#ifdef DEBUG
      Log::Debug2 ("Sending auth response (failed)");
#endif
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
#ifdef DEBUG
  Log::Debug2 ("Sending hash");
#endif
  if (!xSSL_write (ssl, hex_hash, 16, "hash"))
    {
      delete hex_hash;
      return FAIL;
    }

  delete[] hex_hash;

  /* And recv authentication response */
#ifdef DEBUG
  Log::Debug2 ("Recving auth response");
#endif

  if (!xSSL_read (ssl, &auth, sizeof (char), "auth response"))
    return FAIL;

#ifdef DEBUG
  Log::Debug2 ("Server response: %s (%x)",
               (auth ? "auth successfull" : "auth failed"), auth);
#endif

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
  int netCount;

  netCount = hsOpt->allowedNets.NetworkName.size();

#ifdef DEBUG
  Log::Debug2 ("Sending available network count");
#endif
  if (netCount == 0)
    {
#ifdef DEBUG
      Log::Debug2 ("Peer cannot access any networks");
#endif
      xSSL_write (ssl, &netCount, sizeof (int), "network count");
      return FAIL;
    }

  if (!xSSL_write (ssl, &netCount, sizeof (int), "network count"))
    return FAIL;

  /* TODO: add max remote peer capabilities */

  for (i = 0; i < netCount; i++)
    {
      if (!xSSL_write
          (ssl, (char *) hsOpt->allowedNets.NetworkName[i].c_str(), hsOpt->allowedNets.NetworkName[i].length(), "address list"))
        return FAIL;
      if (!xSSL_write
          (ssl, &hsOpt->allowedNets.address[i], sizeof (int), "address list"))
        return FAIL;
      if (!xSSL_write
          (ssl, &hsOpt->allowedNets.netmask[i], sizeof (int), "netmask list"))
        return FAIL;
    }

  return DONE;

}

int Protocol::LulzNetReciveNetworks (SSL * ssl, HandshakeOptionT * hsOpt)
{
  int i;
  int rdLen;
  int netCount;
  int address;
  int netmask;

#ifdef DEBUG
  Log::Debug2 ("Recving available network count");
#endif
  if (!
      (rdLen =
         xSSL_read (ssl, &netCount, sizeof (int), "network count")))
    return FAIL;

  if (netCount == 0)
    {
      Log::Error ("No network available");
      return FAIL;
    }

  for (i = 0; i < netCount && i < MAX_TAPS; i++)
    {
      if (!(rdLen = xSSL_read (ssl, packet, MAX_NETWORKNAME_LEN, "network name list")))
        return FAIL;

      packet[rdLen] = '\x00';
      hsOpt->remoteNets.NetworkName.push_back(packet);

      if (!(rdLen = xSSL_read (ssl, &address, sizeof (int), "address list")))
        return FAIL;

      hsOpt->remoteNets.address.push_back(address);

      if (!(rdLen = xSSL_read (ssl, &netmask, sizeof (int), "netmask list")))
        return FAIL;

      hsOpt->remoteNets.netmask.push_back(netmask);

      hsOpt->remoteNets.network.push_back(get_ip_address_network(address, netmask));
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

#ifdef DEBUG
  Log::Debug2 ("Sending peer count");
#endif
  if (!xSSL_write (ssl, &userCount, sizeof (int), "peer count"))
    return FAIL;

  /* And send peers address */
  for (i = 0; i < userCount; i++)
    {
      sprintf (packet, "%s", userLs.user[i].c_str ());
      if (!xSSL_write (ssl, packet, strlen (packet), "user list"))
        return FAIL;
      if (!xSSL_write
          (ssl, &userLs.address[i], sizeof (int), "address list"))
        return FAIL;
    }

  return DONE;
}

int Protocol::LulzNetReciveUserlist (SSL * ssl, HandshakeOptionT * hsOpt)
{
  int i;
  int rdLen;
  int userCount;
  int address;

  if (!xSSL_read (ssl, &userCount, sizeof (int), "peer count"))
    return FAIL;

  /* And recv peers Log::Info */
  for (i = 0; i < userCount && i < MAX_PEERS; i++)
    {
      if (!(rdLen = xSSL_read (ssl, packet, MAX_USERNAME_LEN, "user list")))
        return FAIL;

      packet[rdLen] = '\x00';
      hsOpt->userLs.user.push_back(packet);

      if (!(rdLen = xSSL_read (ssl, &address, sizeof (int), "address list")))
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

