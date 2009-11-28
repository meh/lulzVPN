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

#include <lulznet/auth.h>
#include <lulznet/config.h>
#include <lulznet/log.h>
#include <lulznet/networking.h>
#include <lulznet/peer.h>
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
  options.ParseConfigFile ((char *) CONFIG_FILE);
  options.ParseArgs (argc, argv);
  options.ChecEmptyConfigEntry ();

  /* Check faggot user */
  if (getuid ())
    Log::Fatal ("You must be super user");

  /* initialize db and other stuff */
  LulznetInit ();

  /* ??? black magic (don't know) */
  tap = new Taps::Tap (options.tap_address (), options.tap_netmask ());

  /* Prompt for password */
  if (options.password().empty())
    Auth::PasswordPrompt();

  /* Start (or not) the listening service */
  if (options.flags () & LISTEN_MODE)
    pthread_create (&server_t, NULL, Network::Server::ServerLoop, NULL);
#ifdef DEBUG
  else
    Log::Debug1 ("Not listening");
#endif

  /* Autoconnection */
  if (!options.connecting_address ().empty ())
    {
      address = Network::LookupAddress (options.connecting_address ());
      if (address != 0)
        Network::Client::PeerConnect (address, options.connecting_port ());
    }

  /* ??? (another black magic) */
  pthread_create (&Network::Server::select_t, NULL, Network::Server::SelectLoop, NULL);

  /* A lovable shell */
  if (options.flags () & INTERPEER_ACTIVE_MODE)
    Shell::Start ();
#ifdef DEBUG
  else
    Log::Debug1 ("Non interactive mode");
#endif

  /* cause we don't like it exits as soon as it starts :| */
  pthread_join (Network::Server::select_t, NULL);
  pthread_join (server_t, NULL);

  return 0;
}

void LulznetInit ()
{
  memset (Peers::db, '\x00', MAX_PEERS * sizeof (Peers::Peer *));
  Peers::count = 0;
  Peers::conections_to_peer = 0;
  Peers::max_fd = 0;

  memset (Taps::db, '\x00', MAX_TAPS * sizeof (Taps::Tap *));
  Taps::count = 0;
  Taps::max_fd = 0;

  FD_ZERO (&Network::master);

  memset (&Network::Server::select_t, '\x00', sizeof (pthread_t));
  pthread_mutex_init (&Peers::db_mutex, NULL);

  SSL_load_error_strings ();
  SSLeay_add_ssl_algorithms ();
  OpenSSL_add_all_digests ();

  Network::Server::SslInit ();
  Network::Client::SslInit ();

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

void LulznetExit ()
{
  int i;

  pthread_mutex_lock(&Peers::db_mutex);
  if (Network::Server::select_t != (pthread_t) NULL)
    pthread_cancel (Network::Server::select_t);

  Log::Info ("Closing lulznet");
  for (i = 0; i < Peers::count; i++)
    Peers::db[i]->Disassociate();

  exit (0);
}

void sigint_handler (int signal __attribute__ ((unused)))
{
  LulznetExit ();
}
