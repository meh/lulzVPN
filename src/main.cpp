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

Config Options;

int main (int argc, char *argv[])
{

  int address;
  uInt i;
  pthread_t serverT;	/* Listening thread */

  /* Welcome!1!1ONE */
  std::cout << "Welcome to lulzNet ¯\\_(O_o)_/¯" << std::endl;
  std::cout << "Lulz p2p Virtual Priv8 Net" << std::endl;
  std::cout << "Version: " << VERSION << std::endl;

  /* Config Parsing */
  Options.ParseConfigFile ((char *) CONFIG_FILE);
  Options.ParseArgs (argc, argv);
  Options.ChecEmptyConfigEntry ();

  /* Check faggot user */
  if (getuid ())
    Log::Fatal ("You must be super user");

  /* initialize db and other stuff */
  LulznetInit ();

  for (i = 0; i < Options.TapDevicesCount(); i++)
    /* ??? black magic (don't know) */
    new Taps::Tap (Options.TapDevice(i));

  /* Prompt for password if no ones is specified in config file*/
  if (Options.Password().empty())
    Auth::PasswordPrompt();

  /* Start (or not) the listening service */
  if (Options.Flags () & LISTENING_MODE)
    pthread_create (&serverT, NULL, Network::Server::ServerLoop, NULL);

  else
    Log::Debug1 ("Not listening");

  /* Autoconnection */
  if (!Options.ConnectingAddress ().empty ())
    {
      address = Network::LookupAddress (Options.ConnectingAddress ());
      if (address != 0)
        Network::Client::PeerConnect (address, Options.ConnectingPort ());
    }

  /* ??? (another black magic) */
  pthread_create (&Network::Server::select_t, NULL, Network::Server::SelectLoop, NULL);

  /* A lovable shell */
  if (Options.Flags () & INTERACTIVE_MODE)
    Shell::Start ();
  else
    Log::Debug1 ("Non interactive mode");

  /* cause I don't enjoy when it exits as soon as it starts :| */
  pthread_join (Network::Server::select_t, NULL);
  pthread_join (serverT, NULL);

  return 0;
}

void LulznetInit ()
{
  Peers::maxFd = 0;
  Taps::maxFd = 0;

  FD_ZERO (&Network::master);

  memset (&Network::Server::select_t, '\x00', sizeof (pthread_t));
  pthread_mutex_init (&Peers::db_mutex, NULL);

  SSL_load_error_strings ();
  SSLeay_add_ssl_algorithms ();
  OpenSSL_add_all_digests ();

  Network::Server::sslInit ();
  Network::Client::sslInit ();

  signal (SIGINT, sigint_handler);
}

void help ()
{
  std::cout << "usage: lulznet [Options]" << std::endl;
  std::cout << "OPTIONS:" << std::endl;
  std::cout << "-b\tspecify server binding address" << std::endl;
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
  uInt i;

  pthread_mutex_lock(&Peers::db_mutex);
  if (Network::Server::select_t != (pthread_t) NULL)
    pthread_cancel (Network::Server::select_t);

  Log::Info ("Closing lulznet");
  for (i = 0; i < Peers::db.size(); i++)
    Peers::db[i]->Disassociate();

  exit (0);
}

void sigint_handler (int signal __attribute__ ((unused)))
{
  LulznetExit ();
}
