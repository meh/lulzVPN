/*
 * "main.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

#include <lulznet/config.h>
#include <lulznet/log.h>
#include <lulznet/networking.h>
#include <lulznet/peer.h>
#include <lulznet/routing.h>
#include <lulznet/shell.h>
#include <lulznet/tap.h>
#include <lulznet/xfunc.h>

Config options;

int main (int argc, char *argv[])
{

  int address;
  Taps::Tap * tap;
  pthread_t server_t;	/* Listening thread */

  /* Wellcome!1!1ONE */
  std::cout << "Wellcome to lulzNet ¯\\_(O_o)_/¯" << std::endl;
  std::cout << "Lulz p2p Virtual Priv8 Net" << std::endl;
  std::cout << "Version: " << VERSION << std::endl;

  /* Config Parsing */
  options.parse_config_file ((char *) CONFIG_FILE);
  options.parse_args (argc, argv);
  options.check_empty_config_entry ();

  /* Check faggot user */
  if (getuid ())
    Log::fatal ("You must be super user");

  /* initialize db and other stuff */
  lulznet_init ();

  /* ??? black magic (don't know) */
  tap = new Taps::Tap (options.tap_address (), options.tap_netmask ());

  /* Start (or not) the listening service */
  if (options.flags () & LISTEN_MODE)
    pthread_create (&server_t, NULL, Network::Server::server_loop, NULL);
  else
    Log::debug1 ("Not listening");

  /* Autoconnection */
  if (!options.connecting_address ().empty ())
    {
      address = Network::lookup_address (options.connecting_address ());
      if (address != 0)
        Network::Client::peer_connect (address, options.connecting_port ());
    }

  /* ??? (another black magic) */
  pthread_create (&Network::Server::select_t, NULL, Network::Server::select_loop, NULL);

  /* A lovable shell */
  if (options.flags () & INTERPEER_ACTIVE_MODE)
    Shell::start ();
  else
    Log::debug1 ("Non interactive mode");

  /* cause we don't like it exits as soon as it starts :| */
  pthread_join (Network::Server::select_t, NULL);
  pthread_join (server_t, NULL);

  return 0;
}

void lulznet_init ()
{
  int sysctl_name[3];
  int sysctl_newval[1];
  int sysctl_newlen;

  memset (Peers::db, '\x00', MAX_PEERS * sizeof (Peers::Peer));
  Peers::count = 0;
  Peers::conections_to_peer = 0;
  Peers::max_fd = 0;

  memset (Taps::db, '\x00', MAX_TAPS * sizeof (Taps::Tap));
  Taps::count = 0;
  Taps::max_fd = 0;

  FD_ZERO (&Network::master);

  memset (&Network::Server::select_t, '\x00', sizeof (pthread_t));
  pthread_mutex_init (&Peers::db_mutex, NULL);

  memset (route_table, '\x00', 512);
  route_entries_count = 0;

  SSL_load_error_strings ();
  SSLeay_add_ssl_algorithms ();
  OpenSSL_add_all_digests ();

  Network::Server::ssl_init ();
  Network::Client::ssl_init ();

  sysctl_name[0] = CTL_NET;
  sysctl_name[1] = NET_IPV4;
  sysctl_name[2] = NET_IPV4_FORWARD;
  sysctl_newlen = sizeof (sysctl_name);
  sysctl_newval[0] = 1;
  sysctl (sysctl_name, 3, NULL, 0, sysctl_newval, sysctl_newlen);

  signal (SIGINT, sigint_handler);
}

void help ()
{
  std::cout << "lulznet :: lulz p2p vpn" << std::endl;
  std::cout << "version " << VERSION << std::endl;
  std::cout << "usage: lulznet [options]" << std::endl;
  std::cout << "OPTIONS:" << std::endl;
  std::cout << "-b\t specify server binding address" << std::endl;
  std::cout << "-c\tspecify a server to connect" << std::endl;
  std::cout << "-h\tdisplay this help" << std::endl;
  std::cout << "-i\tstart interactive shell" << std::endl;
  std::cout << "-l\tspecify user" << std::endl;
  std::cout << "-n\tdisable server listening" << std::endl;
  std::cout << "-p\tspecify connecting port" << std::endl;
  std::cout << "-P\tspecify server listening port" << std::endl;
  std::cout << "-t\tSpecify tap address << std::endl" << std::endl;
  std::cout << "-v\tIncrease debug level << std::endl" << std::endl;

  exit (0);
}

void exit_lulznet ()
{
  int i;

  Log::info ("Closing lulznet");
  for (i = 0; i < Peers::count; i++)
    Peers::db[i]->disassociate();

  exit (0);
}

void sigint_handler (int signal __attribute__ ((unused)))
{
  exit_lulznet ();
}
