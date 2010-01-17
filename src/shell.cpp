/*
 * "shell.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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
#include <lulznet/tap.h>
#include <lulznet/shell.h>
#include <lulznet/xfunc.h>

void
Shell::PeerPreconnect (Cmd * cmd)
{
  int address;
  unsigned short port;

  if (cmd->argc < 1)
    std::cout << "Usage: connect address [port]" << std::endl;
  else if (cmd->argc == 1) {
    address = Network::LookupAddress(cmd->argv[0]);
    if (address == 0)
      return;

    Network::Client::PeerConnect(address, 7890);
  }
  else {
    address = xinet_pton((char *) cmd->argv[0].c_str());
    port = atoi((char *) cmd->argv[1].c_str());

    Network::Client::PeerConnect(address, port);
  }

}

void
Shell::PeerList ()
{
  uInt netCount;
  int nAddr;
  int n_vAddress;
  char pAddr[addressLenght + 1];
  char p_vAddress[addressLenght + 1];
  int cidrNetmask;

  std::vector<Peers::Peer *>::iterator peerIt, peerEnd;
  std::vector<networkT>::const_iterator netIt, netEnd;

  peerEnd = Peers::db.end();
  for (peerIt = Peers::db.begin(); peerIt < peerEnd; ++peerIt) {

    nAddr = (*peerIt)->address();
    inet_ntop(AF_INET, &nAddr, pAddr, addressLenght);

    std::cout << (*peerIt)->user() << "\taddr: " << pAddr << " networks: " << (*peerIt)->nl().size() << std::endl;

    netCount = 1;
    netEnd = (*peerIt)->nl().end();
    for (netIt = (*peerIt)->nl().begin(); netIt < netEnd; ++netIt, ++netCount) {
      n_vAddress = (*netIt).address;
      inet_ntop(AF_INET, &n_vAddress, p_vAddress, addressLenght);

      cidrNetmask = Taps::getCidrNotation(ntohl((*netIt).netmask));

      std::cout << "\t\t[" << netCount << "] addr: " << p_vAddress << "/" << cidrNetmask;
      std::cout << " lid: " << (int) (*netIt).localId << " rid: " << (int) (*netIt).remoteId << std::endl;
    }
  }
}

void
Shell::PeerKill (Cmd * cmd)
{
  std::vector < Peers::Peer * >::iterator peerIt, peerEnd;

  if (cmd->argc != 2)
    std::cout << "Usage: peer kill peer_name" << std::endl;
  else {
    peerEnd = Peers::db.end();
    for (peerIt = Peers::db.begin(); peerIt < peerEnd; ++peerIt)
      if (!(*peerIt)->user().compare(cmd->argv[1])) {
        if ((*peerIt)->isActive()) {
          (*peerIt)->Disassociate();

          Peers::db.erase(peerIt);
          Peers::SetMaxFd();
        }
        else
          std::cout << "Peer is not active" << std::endl;

        return;
      }
    std::cout << "Invalid user specified" << std::endl;
  }
}

void
Shell::TapList ()
{
  int nAddr;
  int nNetm;
  int cidr;
  char pAddr[addressLenght + 1];
  std::vector<Taps::Tap *>::iterator tapIt, tapEnd;

  tapEnd = Taps::db.end();
  for (tapIt = Taps::db.begin(); tapIt < tapEnd; ++tapIt) {

    nAddr = (*tapIt)->address();
    inet_ntop(AF_INET, &nAddr, pAddr, addressLenght);

    nNetm = (*tapIt)->netmask();
    cidr = Taps::getCidrNotation(ntohl(nNetm));

    std::cout << (*tapIt)->device() << "\taddr: " << pAddr << "/" << cidr << std::endl;
  }
}

void
Shell::CredList ()
{
  std::vector<UserCredentialT>::const_iterator ucIt, ucEnd;
  std::vector<std::string>::const_iterator netIt, netEnd;

  ucEnd = Options.UserCredentials().end();
  for (ucIt = Options.UserCredentials().begin(); ucIt < ucEnd; ++ucIt) {
    std::cout << (*ucIt).Name << std::endl;
    std::cout << "\tHash: " << (*ucIt).Hash << std::endl;
    std::cout << "\tAllowed Networks: ";

    netEnd = (*ucIt).AllowedNetworks.end();
    for (netIt =  (*ucIt).AllowedNetworks.begin(); netIt < netEnd; ++netIt)
      std::cout << (*netIt) << " ";
    std::cout << std::endl;
  }
}

void
Shell::Help ()
{
  std::cout << "peer: handle peers" << std::endl;
  std::cout << "tap: handle tap devices" << std::endl;
  std::cout << "cred: handle user credentials" << std::endl;
  std::cout << "connect: connect to a peer" << std::endl;
  std::cout << "whoami: display local peer name" << std::endl;
  std::cout << "password: reset password" << std::endl;
}

Shell::Cmd *
Shell::PreparseCommand (std::string line)
{
  Cmd *command;
  int i;
  char tmp_str[65];
  char *linePtr;
  uInt lineLen;
  uInt tmpLen;
  uInt parsedBytes;

  try {
  command = new Cmd;
  } catch(const std::bad_alloc& x){
    Log::Fatal("Out of memory");
  }
  parsedBytes = 0;

  linePtr = (char *) line.c_str();
  lineLen = line.length();

  /* Read command */
  sscanf(linePtr, "%32s", tmp_str);
  command->command.assign(tmp_str);
  tmpLen = command->command.length() + 1;

  linePtr += tmpLen;
  parsedBytes += tmpLen;

  /* Read arguments */
  for (i = 0; i < 4 && parsedBytes < lineLen; i++) {
    sscanf(linePtr, "%64s", tmp_str);
    command->argv[i] = tmp_str;
    tmpLen = command->argv[i].length() + 1;

    linePtr += tmpLen;
    parsedBytes += tmpLen;
  }

  command->argc = i;

  return command;
}

void
Shell::ParseCommand (Shell::Cmd * cmd)
{

  /* peer command */
  if (!cmd->command.compare("peer")) {
    if (!cmd->argc)
      std::cout << "Usage: peer (list | kill)" << std::endl;
    else if (!cmd->argv[0].compare("list"))
      PeerList();
    else if (!cmd->argv[0].compare("kill"))
      PeerKill(cmd);
    else
      std::cout << "Usage: peer (list | kill)" << std::endl;
  }

  /* tap command */
  else if (!cmd->command.compare("tap")) {
    if (!cmd->argc)
      std::cout << "Usage: tap (list | add | del)" << std::endl;
    else if (!cmd->argv[0].compare("list"))
      TapList();
    else
      std::cout << "Usage: tap (list | add | del)" << std::endl;
  }

  /* credential command */
  else if (!cmd->command.compare("cred")) {
    if (!cmd->argc)
      std::cout << "Usage: cred (list | add | del)" << std::endl;
    else if (!cmd->argv[0].compare("list"))
      CredList();
    else
      std::cout << "Usage: cred (list | add | del)" << std::endl;
  }

  /* connect peer command */
  else if (!cmd->command.compare("connect")) {
    if (!cmd->argc)
      std::cout << "Usage: connect address [port]" << std::endl;
    else
      PeerPreconnect(cmd);
  }

  /* useless command */
  else if (!cmd->command.compare("whoami"))
    std::cout << Options.Username() << std::endl;

  /* reset password */
  else if (!cmd->command.compare("password"))
    Auth::PasswordPrompt();

  else if (!cmd->command.compare("help"))
    Help();

  /* quit command */
  else if (!cmd->command.compare("quit"))
    LulznetExit();

  /* invalid command */
  else
    std::cout << cmd->command.c_str() << ": command not found." << std::endl;
}

void
Shell::Start ()
{
  std::string line;
  char *rlStr;
  Cmd *cmd;
  while (true) {

    rlStr = readline("[lulznet] ");
    if (rlStr != NULL) {
      line = rlStr;
      if (!line.empty()) {
        if ((cmd = PreparseCommand(line))) {
          ParseCommand(cmd);
          add_history(line.c_str());
          line.clear();
        }
        delete cmd;
      }
    }
  }
}
