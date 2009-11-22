/*
 * "protocol.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
 *
 * lulzNet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your hs_option) any later version.
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
char packet[128];

void Protocol::send_banner (int fd)
{

  char banner[512];
  int len;

  sprintf (banner, "LulzNet. Version %s", VERSION);
  len = strlen (banner);
  write (fd, banner, len);
}

void Protocol::recv_banner (int fd)
{

  char banner[512];
  int len;

  len = read (fd, banner, 511);
  banner[len] = '\x00';
  Log::info ("Recv Banner:\n%s", banner);

}

int Protocol::server::handshake (SSL * ssl, hs_opt_t * hs_opt)
{
  /*
   * PROTOCOL!1!1ONE
   */

  /* Exchange peer username */
  if (!ln_user_exchange (ssl, hs_opt))
    return FAIL;

  /* Recv hash and do authentication */
  if (!ln_auth (ssl, hs_opt))
    return FAIL;

#ifdef DEBUG
  Log::debug2 ("Recving listening status");
#endif
  if (!xSSL_read (ssl, packet, sizeof (char), "listening status"))
    return FAIL;

  /* Networks exchange */
  if (!ln_recv_network (ssl, hs_opt))
    return FAIL;

  if (!ln_send_network (ssl, hs_opt))
    return FAIL;

  /* User exchange */
  if (!ln_recv_userlist (ssl, hs_opt))
    return FAIL;

  if (!ln_send_userlist (ssl))
    return FAIL;

  return DONE;
}

int Protocol::client::handshake (SSL * ssl, hs_opt_t * hs_opt)
{

  /*
   * PROTOCOL!1!!ONE
   */

  if (!ln_user_exchange (ssl, hs_opt))
    return FAIL;

  if (!ln_auth (ssl))
    return FAIL;

  /*
   * Hanshake
   */

  /* Peer tells remote peer if it's listening or not */
  /* we need to know this for routing */
#ifdef DEBUG
  Log::debug2 ("Sending listening status");
#endif
  if (options.flags () & LISTEN_MODE)
    packet[0] = 1;
  else
    packet[0] = 0;

  if (!xSSL_write (ssl, packet, sizeof (char), "listening status"))
    return FAIL;

  /* Networks exchange */
  if (!ln_send_network (ssl, hs_opt))
    return FAIL;

  if (!ln_recv_network (ssl, hs_opt))
    return FAIL;

  /* User exchange */
  if (!ln_send_userlist (ssl))
    return FAIL;

  if (!ln_recv_userlist (ssl, hs_opt))
    return FAIL;

  return DONE;
}

int Protocol::server::ln_user_exchange (SSL * ssl, hs_opt_t * hs_opt)
{
  int rd_len;

#ifdef DEBUG
  Log::debug2 ("Recving username");
#endif
  if (!(rd_len = xSSL_read (ssl, packet, MAX_USERNAME_LEN, "username")))
    return FAIL;

  hs_opt->peer_username.assign (packet);

  if (Peers::user_is_connected ((char *) hs_opt->peer_username.c_str ()))
    {
      Log::error("User is connected");
      packet[0] = 0;
      xSSL_write (ssl, packet, 1, "user info");
      return FAIL;
    }

  if ((!hs_opt->peer_username.compare (options.username ())))
    {
      Log::error("User is connected (same as local peer)");
      packet[0] = 0;
      xSSL_write (ssl, packet, 1, "user info");
      return FAIL;
    }

  packet[0] = 1;
  if (!xSSL_write (ssl, packet, 1, "user info"))
    return FAIL;

  /* And send its username */
#ifdef DEBUG
  Log::debug2 ("Sending username");
#endif
  if (!xSSL_write
      (ssl, (void *) options.username ().c_str (),
       options.username ().length (), "username"))
    return FAIL;

  return DONE;
}

int Protocol::client::ln_user_exchange (SSL * ssl, hs_opt_t * hs_opt)
{
  int rd_len;

  /* Peer send its username */
#ifdef DEBUG
  Log::debug2 ("Sending username");
#endif
  if (!xSSL_write
      (ssl, (char *) options.username ().c_str (),
       options.username ().length (), "username"))
    return FAIL;

  xSSL_read (ssl, packet, 1, "user info");
  if (packet[0] == 0)
    {
      Log::error ("user is connected");
      return FAIL;
    }

  /* And recv remote peer username */
#ifdef DEBUG
  Log::debug2 ("Recving username");
#endif
  if (!(rd_len = xSSL_read (ssl, packet, MAX_USERNAME_LEN, "username")))
    return FAIL;

  hs_opt->peer_username.assign (packet);

  return DONE;
}

int Protocol::server::ln_auth (SSL * ssl, hs_opt_t * hs_opt)
{

  u_char hex_hash[16];
  char auth;

  /* Recv hash */
#ifdef DEBUG
  Log::debug2 ("Recving hash");
#endif
  if (!xSSL_read (ssl, hex_hash, 16, "hash"))
    return FAIL;

  /* Do authentication checking if hash match local credential file's hash */
  if (Auth::do_authentication (hs_opt->peer_username, hex_hash))
    {
      auth = AUTHENTICATION_SUCCESSFULL;
#ifdef DEBUG
      Log::debug2 ("Sending auth response (successfull)");
#endif
      if (!xSSL_write (ssl, &auth, sizeof (char), "auth response"))
        return FAIL;
    }
  else
    {
      auth = AUTHENTICATION_FAILED;
#ifdef DEBUG
      Log::debug2 ("Sending auth response (failed)");
#endif
      xSSL_write (ssl, &auth, sizeof (char), "auth response");
      return FAIL;
    }

  return DONE;
}

int Protocol::client::ln_auth (SSL * ssl)
{

  u_char *hex_hash;
  char auth;

  hex_hash = Auth::Crypt::calculate_md5 (options.password());

  /* Then send password's hash */
#ifdef DEBUG
  Log::debug2 ("Sending hash");
#endif
  if (!xSSL_write (ssl, hex_hash, 16, "hash"))
    {
      delete hex_hash;
      return FAIL;
    }

  delete hex_hash;

  /* And recv authentication response */
#ifdef DEBUG
  Log::debug2 ("Recving auth response");
#endif

  if (!xSSL_read (ssl, &auth, sizeof (char), "auth response"))
    return FAIL;

#ifdef DEBUG
  Log::debug2 ("Server response: %s (%x)",
               (auth ? "auth successfull" : "auth failed"), auth);
#endif

  if (auth == AUTHENTICATION_FAILED)
    {
      Log::error ("Authentication failed");
      return FAIL;
    }
  return DONE;
}

int Protocol::ln_send_network (SSL * ssl, hs_opt_t * hs_opt)
{
  int i;
  net_ls_t local_net_ls;

  local_net_ls = Taps::get_user_allowed_networks ((char *) hs_opt->peer_username.c_str ());

#ifdef DEBUG
  Log::debug2 ("Sending available network count");
#endif
  if (local_net_ls.count == 0)
    {
#ifdef DEBUG
      Log::debug2 ("Peer cannot access any networks");
#endif
      xSSL_write (ssl, &local_net_ls.count, sizeof (int), "network count");
      return FAIL;
    }

  if (!xSSL_write (ssl, &local_net_ls.count, sizeof (int), "network count"))
    return FAIL;

  /* TODO: add max remote peer capabilities */

  for (i = 0; i < local_net_ls.count; i++)
    {

      if (!xSSL_write
          (ssl, &local_net_ls.network[i], sizeof (int), "network list"))
        return FAIL;

      if (!xSSL_write
          (ssl, &local_net_ls.netmask[i], sizeof (int), "netmask list"))
        return FAIL;

    }

  return DONE;

}

int Protocol::ln_recv_network (SSL * ssl, hs_opt_t * hs_opt)
{
  int i;
  int rd_len;

#ifdef DEBUG
  Log::debug2 ("Recving available network count");
#endif
  if (!
      (rd_len =
         xSSL_read (ssl, &hs_opt->net_ls.count, sizeof (int), "network count")))
    return FAIL;

  if (hs_opt->net_ls.count == 0)
    {
      Log::error ("No network available");
      return FAIL;
    }

  hs_opt->net_ls.network = new int[hs_opt->net_ls.count];
  hs_opt->net_ls.netmask = new int[hs_opt->net_ls.count];

  for (i = 0; i < hs_opt->net_ls.count && i < MAX_TAPS; i++)
    {
      if (!(rd_len = xSSL_read (ssl, &hs_opt->net_ls.network[i], sizeof (int), "network list")))
        return FAIL;
      if (!
          (rd_len =
             xSSL_read (ssl, &hs_opt->net_ls.netmask[i], sizeof (int),
                        "netmask list")))

        return FAIL;
    }

  return DONE;
}

int Protocol::ln_send_userlist (SSL * ssl)
{
  int i;
  user_ls_t user_ls;
  user_ls = Protocol::get_userlist ();

#ifdef DEBUG
  Log::debug2 ("Sending peer count");
#endif
  if (!xSSL_write (ssl, &user_ls.count, sizeof (int), "peer count"))
    return FAIL;

  /* And send peers address */
  for (i = 0; i < user_ls.count; i++)
    {
      sprintf (packet, "%s", user_ls.user[i].c_str ());
      if (!xSSL_write (ssl, packet, strlen (packet), "user list"))
        return FAIL;
      if (!xSSL_write
          (ssl, &user_ls.address[i], sizeof (int), "address list"))
        return FAIL;
    }

  return DONE;
}

int Protocol::ln_recv_userlist (SSL * ssl, hs_opt_t * hs_opt)
{
  int i;

  int rd_len;

  if (!xSSL_read (ssl, &hs_opt->user_ls.count, sizeof (int), "peer count"))
    return FAIL;

  hs_opt->user_ls.user = new std::string[hs_opt->user_ls.count];
  hs_opt->user_ls.address = new int[hs_opt->user_ls.count];

  /* And recv peers Log::info */
  for (i = 0; i < hs_opt->user_ls.count && i < MAX_PEERS; i++)
    {
      if (!(rd_len = xSSL_read (ssl, packet, MAX_USERNAME_LEN, "user list")))
        return FAIL;

      packet[rd_len] = '\x00';
      hs_opt->user_ls.user[i].assign (packet);

      if (!
          (rd_len =
             xSSL_read (ssl, &hs_opt->user_ls.address[i], sizeof (int),
                        "address list")))
        return FAIL;

    }
  return DONE;

}

user_ls_t Protocol::get_userlist ()
{

  int i;
  Peers::Peer * peer;

  user_ls_t user_ls;

  user_ls.user = new std::string[Peers::count];
  user_ls.address = new int[Peers::count];
  user_ls.count = Peers::count;

  for (i = 0; i < Peers::count; i++)
    {
      peer = Peers::db[i];

      user_ls.user[i] = peer->user ();
      user_ls.address[i] = peer->address ();
    }

  return user_ls;
}

