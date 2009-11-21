/*
 * "peer.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
 *
 * lulzNet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * lulzNet is distributed in the hope that it will be useful,
 * but WITH ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
*/

#include <lulznet/lulznet.h>

#include <lulznet/config.h>
#include <lulznet/log.h>
#include <lulznet/networking.h>
#include <lulznet/peer.h>
#include <lulznet/protocol.h>
#include <lulznet/tap.h>
#include <lulznet/xfunc.h>

Peers::Peer * Peers::db[MAX_PEERS];
pthread_mutex_t Peers::db_mutex;
int Peers::count;
int Peers::conections_to_peer;
int Peers::max_fd;

void
Peers::set_max_fd ()
{
  int i;
  max_fd = 0;

  for (i = 0; i < count; i++)
    if (db[i]->fd() > max_fd)
      max_fd = db[i]->fd();
}

Peers::Peer::Peer (int fd, SSL * ssl, std::string user, int address, net_ls_t nl, char type)
{
  _fd = fd;
  _ssl = ssl;

  _state = PEER_ACTIVE;
  _type = type;

  if (type == OUTGOING_CONNECTION)
    conections_to_peer++;

  _address = address;
  _user = user;

  _nl = nl;

  db[count] = this;

  count++;
  set_max_fd ();

  FD_SET (_fd, &Network::master);
  Log::debug2 ("Added fd %d to fd_set master (1st free fd: %d)", fd, count);

  /* restart select thread so select() won't block world */
  Network::Server::restart_select_loop ();
}


Peers::Peer::~Peer ()
{
  SSL_free (_ssl);

  if (_type == OUTGOING_CONNECTION)
    conections_to_peer--;

  FD_CLR (_fd, &Network::master);
  close (_fd);

  Log::debug2 ("Removed fd %d from fd_set master (current fd %d)", _fd,
               count);
}

bool
Peers::Peer::operator>> (Network::Packet * packet)
{
  if (!(packet->length = xSSL_read (_ssl, packet->buffer, 4096, "forwarding data")))
    {
      _state = PEER_CLOSING;
      return FAIL;
    }

  Log::debug3 ("Read %d bytes packet from peer %s", packet->length, _user.c_str());
  return DONE;
}

bool
Peers::Peer::operator<< (Network::Packet * packet)
{
  if (!xSSL_write (_ssl, packet->buffer, packet->length + 1, "forwarding data"))
    {
      _state = PEER_CLOSING;
      return FAIL;
    }

  Log::debug3 ("\tForwarded to peer %s",_user.c_str());
  return DONE;
}

bool Peers::Peer::isActive()
{
  if (_state == PEER_ACTIVE)
    return true;

  return false;
}

bool Peers::Peer::isReadyToRead(fd_set *rd_sel)
{
  if (FD_ISSET (_fd, rd_sel))
    return true;

  return false;
}

void Peers::Peer::setClosing()
{
  _state = PEER_CLOSING;
}

int Peers::Peer::fd()
{
  return _fd;
}

std::string Peers::Peer::user ()
{

  return _user;
}

int Peers::Peer::address ()
{
  return _address;
}

net_ls_t Peers::Peer::nl ()
{
  return _nl;
}


void Peers::free_non_active ()
{
  int i;

  Log::debug2 ("freeing non active fd");
  for (i = 0; i < count; i++)
    if (!db[i]->isActive ())
      {
        Taps::set_system_routing (db[i], DEL_ROUTING);
        delete db[i];
        db[i] = NULL;
      }

  rebuild_db ();
}

void
Peers::rebuild_db ()
{
  int i;
  int j;
  int freed_peer;

  freed_peer = 0;
  j = 0;

  for (i = 0; i < count; i++)
    if (db[i] != NULL)
      db[j++] = db[i];
    else
      freed_peer++;

  count -= freed_peer;
  set_max_fd ();
}

void
Peers::Peer::disassociate ()
{
  char packet[3];

  packet[0] = CONTROL_PACKET;
  packet[1] =  CLOSE_CONNECTION;
  xSSL_write (_ssl, packet, 2, "disconnection packet");

  Taps::set_system_routing (this, DEL_ROUTING);
  delete this;
}

Peers::Peer * Peers::get_fd_related (int fd)
{
  int i;

  for (i = 0; i < MAX_PEERS; i++)
    if (db[i]->isActive ()&& db[i]->fd () == fd)
      return db[i];

  return NULL;
}

int Peers::user_is_connected (char *user)
{
  int i;

  for (i = 0; i < count; i++)
    if (db[i]->isActive())
      if (!db[i]->user ().compare (user))
        return TRUE;

  return FALSE;
}
