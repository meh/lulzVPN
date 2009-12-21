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

void Shell::PeerPreconnect (Cmd * cmd)
{
  int address;
  unsigned short port;

  if (cmd->argc < 1)
    std::cout << "Usage: connect address [port]" << std::endl;
  else if (cmd->argc == 1)
    {
      address = Network::LookupAddress (cmd->argv[0]);
      if (address == 0)
        return;

      Network::Client::PeerConnect (address, 7890);
    }
  else
    {
      address = xinet_pton ((char *) cmd->argv[0].c_str ());
      port = atoi ((char *) cmd->argv[1].c_str ());

      Network::Client::PeerConnect (address, port);
    }

}

void Shell::PeerList ()
{
  uInt i;
  uInt j;
  int nAddr;
  int n_vAddress;
  char pAddr[ADDRESS_LEN + 1];
  char p_vAddress[ADDRESS_LEN + 1];
  int cidrNetmask;
  Peers::Peer * peer;

  for (i = 0; i < Peers::db.size(); i++)
    {
      peer = Peers::db[i];

      nAddr = peer->address ();
      inet_ntop (AF_INET, &nAddr, pAddr, ADDRESS_LEN);

      std::cout << peer->user() << "\taddr: " << pAddr << " networks: " << peer->nl().NetworkName.size() << std::endl;

      for (j = 0; j < peer->nl().NetworkName.size(); j++)
        {
          n_vAddress = peer->nl().address[j];
          inet_ntop (AF_INET, &n_vAddress, p_vAddress, ADDRESS_LEN);

          cidrNetmask = Taps::getCidrNotation(ntohl(peer->nl().netmask[i]));

          std::cout << "\t\t[" << j + 1 << "] addr: " << p_vAddress << "/" << cidrNetmask << std::endl;
        }
    }
}

void Shell::PeerKill (Cmd * cmd)
{
  uInt i;
  std::vector<Peers::Peer *>::iterator it;

  if (cmd->argc != 2)
    std::cout << "Usage: peer kill peer_name" << std::endl;
  else
    {
      for ( i = 0; i < Peers::db.size(); i++)
        if (!Peers::db[i]->user().compare(cmd->argv[1]))
          {
            if (Peers::db[i]->isActive())
              {
                Peers::db[i]->Disassociate();

                it = Peers::db.begin();
                it+=i;
                Peers::db.erase(it);
                Peers::SetMaxFd();
              }
            else
              std::cout << "Peer is not active" << std::endl;

            return;
          }
      std::cout << "Invalid user specified" << std::endl;
    }
}

void Shell::TapList ()
{
  uInt i;
  int nAddr;
  int nNetm;
  int cidr;
  char pAddr[ADDRESS_LEN + 1];
  Taps::Tap * tap;

  for (i = 0; i < Taps::db.size(); i++)
    {
      tap = Taps::db[i];

      nAddr = tap->address();
      inet_ntop (AF_INET, &nAddr, pAddr, ADDRESS_LEN);

      nNetm = tap->netmask();
      cidr = Taps::getCidrNotation(ntohl(nNetm));

      std::cout << tap->device () << "\taddr: " << pAddr << "/" << cidr << std::endl;
    }
}

void Shell::CredList ()
{
  uInt i;
  unsigned int j;

  for (i = 0; i < Options.UserCredentialsCount(); i++)
    {
      std::cout << Options.UserCredentials(i).Name << std::endl;
      std::cout << "\tHash: " << Options.UserCredentials(i).Hash << std::endl;
      std::cout << "\tAllowed Networks: ";
      for (j = 0; j < Options.UserCredentials(i).AllowedNetworks.size(); j++)
        std::cout << Options.UserCredentials(i).AllowedNetworks[j] << " ";
      std::cout << std::endl;
    }
}

void
Shell::Help()
{
  std::cout << "peer: handle peers"<< std::endl ;
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

  command = new Cmd;
  parsedBytes = 0;

  linePtr = (char *) line.c_str ();
  lineLen = line.length();

  /* Read command */
  sscanf (linePtr, "%32s", tmp_str);
  command->command.assign (tmp_str);
  tmpLen = command->command.length () + 1;

  linePtr += tmpLen;
  parsedBytes += tmpLen;

  /* Read arguments */
  for (i = 0; i < 4 && parsedBytes < lineLen; i++)
    {
      sscanf (linePtr, "%64s", tmp_str);
      command->argv[i] = tmp_str;
      tmpLen = command->argv[i].length () + 1;

      linePtr += tmpLen;
      parsedBytes += tmpLen;
    }

  command->argc = i;

  return command;
}

void Shell::ParseCommand (Shell::Cmd * cmd)
{

  /* peer command */
  if (!cmd->command.compare ("peer"))
    {
      if (!cmd->argc)
        std::cout << "Usage: peer (list | kill)" << std::endl;
      else if (!cmd->argv[0].compare ("list"))
        PeerList ();
      else if (!cmd->argv[0].compare ("kill"))
        PeerKill (cmd);
      else
        std::cout << "Usage: peer (list | kill)" << std::endl;
    }

  /* tap command */
  else if (!cmd->command.compare ("tap"))
    {
      if (!cmd->argc)
        std::cout << "Usage: tap (list | add | del)" << std::endl;
      else if (!cmd->argv[0].compare ("list"))
        TapList ();
      else
        std::cout << "Usage: tap (list | add | del)" << std::endl;
    }

  /* credential command */
  else if (!cmd->command.compare ("cred"))
    {
      if (!cmd->argc)
        std::cout << "Usage: cred (list | add | del)" << std::endl;
      else if (!cmd->argv[0].compare ("list"))
        CredList ();
      else
        std::cout << "Usage: cred (list | add | del)" << std::endl;
    }

  /* connect peer command */
  else if (!cmd->command.compare ("connect"))
    {
      if (!cmd->argc)
        std::cout << "Usage: connect address [port]" << std::endl;
      else
        PeerPreconnect (cmd);
    }

  /* useless command */
  else if (!cmd->command.compare ("whoami"))
    std::cout << Options.Username() << std::endl;

  /* reset password */
  else if (!cmd->command.compare ("password"))
    Auth::PasswordPrompt();

  else if (!cmd->command.compare ("help"))
    Help();

  /* quit command */
  else if (!cmd->command.compare ("quit"))
    LulznetExit ();

  /* invalid command */
  else
    std::cout << cmd->command.c_str () << ": command not found." << std::endl;
}

void Shell::Start ()
{
  std::string line;
  char *rlStr;
  Cmd *cmd;
  while (TRUE)
    {

      rlStr = readline ("[lulznet] ");
      if (rlStr != NULL)
        {
          line = rlStr;
          if (!line.empty ())
            {
              if ((cmd = PreparseCommand (line)))
                {
                  ParseCommand (cmd);
                  add_history (line.c_str ());
                  line.clear();
                }
              delete cmd;
            }
        }
    }
}
