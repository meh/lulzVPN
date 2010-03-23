/*
 * "main.cpp" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
 *
 * lulzVPN is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * lulzVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */

#include <lulzvpn/lulzvpn.h>

#include <lulzvpn/auth.h>
#include <lulzvpn/config.h>
#include <lulzvpn/log.h>
#include <lulzvpn/networking.h>
#include <lulzvpn/peer_api.h>
#include <lulzvpn/select.h>
#include <lulzvpn/shell.h>
#include <lulzvpn/tap_api.h>
#include <lulzvpn/xfunc.h>

Config Options;

int
main (int argc, char *argv[])
{

  int address;

  /* Welcome!1!1ONE */
  std::cout << " _       _    __     ______  _   _" << std::endl;
  std::cout << "| |_   _| |____ \\   / /  _ \\| \\ | |" << std::endl;
  std::cout << "| | | | | |_  /\\ \\ / /| |_) |  \\| |" << std::endl;
  std::cout << "| | |_| | |/ /  \\ V / |  __/| |\\  |" << std::endl;
  std::cout << "|_|\\__,_|_/___|  \\_/  |_|   |_| \\_| " << std::endl;
  std::cout << "\t\tVersion: " << PACKAGE_VERSION << std::endl;
  std::cout << std::endl;

  /* Check faggot user */
  if (getuid())
    Log::Fatal("You must be super user");

  /* Config Parsing */
  Options.ParseConfigFile(CONFIG_FILE);
  Options.ParseArgs(argc, argv);
  Options.ChecEmptyConfigEntry();

  /* initialize db, taps and other stuff */
  LulzVPNInit();

  /* Prompt for password if no ones is specified in config file */
  if (Options.Password().empty())
    Auth::PasswordPrompt();

  /* Start client data channel, ctrl channel and tap channel */
  pthread_create(&Select::DataChannel::Client::ThreadId, NULL, Select::DataChannel::Client::Loop, NULL);
  pthread_create(&Select::CtrlChannel::ThreadId, NULL, Select::CtrlChannel::Loop, NULL);
  pthread_create(&Select::TapChannel::ThreadId, NULL, Select::TapChannel::Loop, NULL);

  /* Start the listening service */
  if (Options.Flags() & listeningMode) {
    pthread_create(&Select::DataChannel::Server::ThreadId, NULL, Select::DataChannel::Server::Loop, NULL);
    pthread_create(&Network::Server::ServerLoopT, NULL, Network::Server::ServerLoop, NULL);
  }

  /* Handle autoconnection */
  if (!Options.ConnectingAddress().empty()) {
    address = Network::LookupAddress(Options.ConnectingAddress());
    if (address != 0)
      Network::Client::PeerConnect(address, Options.ConnectingPort());
    else
      Log::Error("Cannot resolve address %s",Options.ConnectingAddress().c_str());
  }

  /* Start a lovable shell */
  if (Options.Flags() & interactiveMode)
    Shell::Start();

  pthread_join(Network::Server::ServerLoopT, NULL);

  return 0;
}

void
LulzVPNInit ()
{
  std::vector<TapDeviceT>::const_iterator tapIt, tapEnd;
  Taps::Tap *newTap;

  /* Initialize maxFd vars*/
  Peers::maxTcpFd = 0;
  Peers::maxUdpFd = 0;
  Taps::maxFd = 0;

//#pragma warning (disable:593)
  FD_ZERO(&Select::DataChannel::Client::Set);
  FD_ZERO(&Select::CtrlChannel::Set);
  FD_ZERO(&Select::TapChannel::Set);
//#pragma warning (default:593)

  /* Clear pthread_t */
  memset(&Select::DataChannel::Client::ThreadId, '\x00', sizeof(pthread_t));
  memset(&Select::DataChannel::Server::ThreadId, '\x00', sizeof(pthread_t));
  memset(&Select::CtrlChannel::ThreadId, '\x00', sizeof(pthread_t));
  memset(&Select::TapChannel::ThreadId, '\x00', sizeof(pthread_t));

  pthread_mutex_init(&Peers::db_mutex, NULL);

  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();
  OpenSSL_add_all_digests();

  signal(SIGHUP, sigHandler);
  signal(SIGINT, sigHandler);

  Network::Client::sslInit();

  if (Options.Flags() & listeningMode) {
    Network::Server::sslInit();
    Network::Server::UdpRecverInit();
  }

  /* ??? black magic (don't know) */
  tapEnd = Options.TapDevices().end();
  for (tapIt = Options.TapDevices().begin(); tapIt < tapEnd; ++tapIt) {
    try {
      newTap = new Taps::Tap(*tapIt);
      Taps::Register(newTap);
    } catch(const std::bad_alloc) {
	 Log::Fatal("Out of memory");
    }
  }
}

void
help ()
{
  std::cout << "usage: lulzvpn [Options]" << std::endl;
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

  exit(0);
}

void
LulzVPNExit ()
{
  std::vector<Peers::Peer *>::iterator peerIt, peerEnd;

  pthread_mutex_lock(&Peers::db_mutex);
  if (Network::Server::ServerLoopT != (pthread_t) NULL)
    pthread_cancel(Network::Server::ServerLoopT);

  Log::Info("Closing lulzvpn");
  peerEnd = Peers::db.end();
  for (peerIt = Peers::db.begin(); peerIt < peerEnd; ++peerIt)
    (*peerIt)->Disassociate();

  exit(0);
}

void
sigHandler (int signal __attribute__ ((unused)))
{
  LulzVPNExit();
}

