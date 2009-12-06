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
  int i;
  int j;
  int n_address;
  int n_vAddress;
  char p_address[ADDRESS_LEN + 1];
  char p_vAddress[ADDRESS_LEN + 1];
  int cidrNetmask;
  Peers::Peer * peer;

  for (i = 0; i < Peers::count; i++)
    {
      peer = Peers::db[i];

      n_address = peer->address ();
      inet_ntop (AF_INET, &n_address, p_address, ADDRESS_LEN);

      std::cout << peer->user() << "\taddr: " << p_address << " networks: " << peer->nl().count << std::endl;

      for (j = 0; j < peer->nl().count; j++)
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
  int i;

  if (cmd->argc != 2)
    std::cout << "Usage: peer kill peer_name" << std::endl;
  else
    {
      for ( i = 0; i < Peers::count; i++)
        if (!Peers::db[i]->user().compare(cmd->argv[1]))
          {
            if (Peers::db[i]->isActive())
              {
                Peers::db[i]->Disassociate();
                Peers::db[i] = NULL;
                Peers::RebuildDb();
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
  int i;
  int n_address;
  int n_netmask;
  int netmask;
  char p_address[ADDRESS_LEN + 1];
  Taps::Tap * tap;

  for (i = 0; i < Taps::count; i++)
    {
      tap = Taps::db[i];

      n_address = tap->address();
      n_netmask = tap->netmask();
      inet_ntop (AF_INET, &n_address, p_address, ADDRESS_LEN);
      netmask = Taps::getCidrNotation(ntohl(n_netmask));

      std::cout << tap->device () << "\taddr: " << p_address << "/" << netmask << std::endl;
    }
}

void
Shell::Help()
{
  std::cout << "peer: handle peer"<< std::endl ;
  std::cout << "tap: handle tap device" << std::endl;
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
  char *line_ptr;
  u_int line_len;
  u_int tmp_len;
  u_int parsed_bytes;

  command = new Cmd;
  parsed_bytes = 0;

  line_ptr = (char *) line.c_str ();
  line_len = line.length();

  /* Read command */
  sscanf (line_ptr, "%32s", tmp_str);
  command->command.assign (tmp_str);
  tmp_len = command->command.length () + 1;

  line_ptr += tmp_len;
  parsed_bytes += tmp_len;

  /* Read arguments */
  for (i = 0; i < 4 && parsed_bytes < line_len; i++)
    {
      sscanf (line_ptr, "%64s", tmp_str);
      command->argv[i] = tmp_str;
      tmp_len = command->argv[i].length () + 1;

      line_ptr += tmp_len;
      parsed_bytes += tmp_len;
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
    std::cout << options.username() << std::endl;

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
  char *readline_str;
  Cmd *cmd;
  while (TRUE)
    {

      readline_str = readline ("[lulznet] ");
      if (readline_str != NULL)
        {
          line = readline_str;
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
