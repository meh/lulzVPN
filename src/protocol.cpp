/*
 * "protocol.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
 *
 * lulzNet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your hsOption) any later version.
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

int Protocol::server::Handshake (SSL * ssl, hsOptT * hsOpt)
{
  /*
   * PROTOCOL!1!1ONE
   */

  /* Exchange peer username */
  if (!LnUserExchange (ssl, hsOpt))
    return FAIL;

  /* Recv hash and do authentication */
  if (!LnAuth (ssl, hsOpt))
    return FAIL;

#ifdef DEBUG
  Log::Debug2 ("Recving listening status");
#endif
  if (!xSSL_read (ssl, packet, sizeof (char), "listening status"))
    return FAIL;

  /* Networks exchange */
  if (!LnRecvNetworks (ssl, hsOpt))
    return FAIL;

  if (!LnSendNetworks (ssl, hsOpt))
    return FAIL;

  /* User exchange */
  if (!LnRecvUserlist (ssl, hsOpt))
    return FAIL;

  if (!LnSendUserlist (ssl))
    return FAIL;

  return DONE;
}

int Protocol::client::Handshake (SSL * ssl, hsOptT * hsOpt)
{

  /*
   * PROTOCOL!1!!ONE
   */

  if (!LnUserExchange (ssl, hsOpt))
    return FAIL;

  if (!LnAuth (ssl))
    return FAIL;

  /*
   * Hanshake
   */

  /* Peer tells remote peer if it's listening or not */
  /* we need to know this for routing */
#ifdef DEBUG
  Log::Debug2 ("Sending listening status");
#endif
  if (options.flags () & LISTEN_MODE)
    packet[0] = 1;
  else
    packet[0] = 0;

  if (!xSSL_write (ssl, packet, sizeof (char), "listening status"))
    return FAIL;

  /* Networks exchange */
  if (!LnSendNetworks (ssl, hsOpt))
    return FAIL;

  if (!LnRecvNetworks (ssl, hsOpt))
    return FAIL;

  /* User exchange */
  if (!LnSendUserlist (ssl))
    return FAIL;

  if (!LnRecvUserlist (ssl, hsOpt))
    return FAIL;

  return DONE;
}

int Protocol::server::LnUserExchange (SSL * ssl, hsOptT * hsOpt)
{
  int rd_len;

#ifdef DEBUG
  Log::Debug2 ("Recving username");
#endif
  if (!(rd_len = xSSL_read (ssl, packet, MAX_USERNAME_LEN, "username")))
    return FAIL;

  packet[rd_len] = '\x00';
  hsOpt->peer_username.assign (packet);

  if (Peers::UserIsConnected ((char *) hsOpt->peer_username.c_str ()))
    {
      Log::Error("User is connected");
      packet[0] = 0;
      xSSL_write (ssl, packet, 1, "user info");
      return FAIL;
    }

  if ((!hsOpt->peer_username.compare (options.username ())))
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
      (ssl, (void *) options.username ().c_str (),
       options.username ().length (), "username"))
    return FAIL;

  return DONE;
}

int Protocol::client::LnUserExchange (SSL * ssl, hsOptT * hsOpt)
{
  int rd_len;

  /* Peer send its username */
#ifdef DEBUG
  Log::Debug2 ("Sending username");
#endif
  if (!xSSL_write
      (ssl, (char *) options.username ().c_str (),
       options.username ().length (), "username"))
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
  if (!(rd_len = xSSL_read (ssl, packet, MAX_USERNAME_LEN, "username")))
    return FAIL;
  packet[rd_len] = '\x00';
  hsOpt->peer_username.assign (packet);

  return DONE;
}

int Protocol::server::LnAuth (SSL * ssl, hsOptT * hsOpt)
{

  u_char hex_hash[16];
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

int Protocol::client::LnAuth (SSL * ssl)
{

  u_char *hex_hash;
  char auth;

  hex_hash = Auth::Crypt::CalculateMd5 (options.password());

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

int Protocol::LnSendNetworks (SSL * ssl, hsOptT * hsOpt)
{
  int i;
  netLsT local_netLs;

  local_netLs = Taps::getUserAllowedNetworks ((char *) hsOpt->peer_username.c_str ());

#ifdef DEBUG
  Log::Debug2 ("Sending available network count");
#endif
  if (local_netLs.count == 0)
    {
#ifdef DEBUG
      Log::Debug2 ("Peer cannot access any networks");
#endif
      xSSL_write (ssl, &local_netLs.count, sizeof (int), "network count");
      return FAIL;
    }

  if (!xSSL_write (ssl, &local_netLs.count, sizeof (int), "network count"))
    return FAIL;

  /* TODO: add max remote peer capabilities */

  for (i = 0; i < local_netLs.count; i++)
    {

      if (!xSSL_write
          (ssl, &local_netLs.address[i], sizeof (int), "address list"))
        return FAIL;
      if (!xSSL_write
          (ssl, &local_netLs.netmask[i], sizeof (int), "netmask list"))
        return FAIL;

    }

  return DONE;

}

int Protocol::LnRecvNetworks (SSL * ssl, hsOptT * hsOpt)
{
  int i;
  int rd_len;

#ifdef DEBUG
  Log::Debug2 ("Recving available network count");
#endif
  if (!
      (rd_len =
         xSSL_read (ssl, &hsOpt->netLs.count, sizeof (int), "network count")))
    return FAIL;

  if (hsOpt->netLs.count == 0)
    {
      Log::Error ("No network available");
      return FAIL;
    }

  hsOpt->netLs.address = new int[hsOpt->netLs.count];
  hsOpt->netLs.netmask = new int[hsOpt->netLs.count];
  hsOpt->netLs.network = new int[hsOpt->netLs.count];

  for (i = 0; i < hsOpt->netLs.count && i < MAX_TAPS; i++)
    {
      if (!(rd_len = xSSL_read (ssl, &hsOpt->netLs.address[i], sizeof (int), "address list")))
        return FAIL;
      if (!(rd_len = xSSL_read (ssl, &hsOpt->netLs.netmask[i], sizeof (int), "netmask list")))
        return FAIL;
      hsOpt->netLs.network[i] = get_ip_address_network(hsOpt->netLs.address[i],hsOpt->netLs.netmask[i]);
    }

  return DONE;
}

int Protocol::LnSendUserlist (SSL * ssl)
{
  int i;
  userLsT userLs;
  userLs = Protocol::GetUserlist ();

#ifdef DEBUG
  Log::Debug2 ("Sending peer count");
#endif
  if (!xSSL_write (ssl, &userLs.count, sizeof (int), "peer count"))
    return FAIL;

  /* And send peers address */
  for (i = 0; i < userLs.count; i++)
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

int Protocol::LnRecvUserlist (SSL * ssl, hsOptT * hsOpt)
{
  int i;

  int rd_len;

  if (!xSSL_read (ssl, &hsOpt->userLs.count, sizeof (int), "peer count"))
    return FAIL;

  hsOpt->userLs.user = new std::string[hsOpt->userLs.count];
  hsOpt->userLs.address = new int[hsOpt->userLs.count];

  /* And recv peers Log::Info */
  for (i = 0; i < hsOpt->userLs.count && i < MAX_PEERS; i++)
    {
      if (!(rd_len = xSSL_read (ssl, packet, MAX_USERNAME_LEN, "user list")))
        return FAIL;

      packet[rd_len] = '\x00';
      hsOpt->userLs.user[i].assign (packet);

      if (!(rd_len = xSSL_read (ssl, &hsOpt->userLs.address[i], sizeof (int), "address list")))
        return FAIL;

    }
  return DONE;

}

userLsT Protocol::GetUserlist ()
{

  int i;
  Peers::Peer * peer;

  userLsT userLs;

  userLs.user = new std::string[Peers::count];
  userLs.address = new int[Peers::count];
  userLs.count = Peers::count;

  for (i = 0; i < Peers::count; i++)
    {
      peer = Peers::db[i];

      userLs.user[i] = peer->user ();
      userLs.address[i] = peer->address ();
    }

  return userLs;
}

