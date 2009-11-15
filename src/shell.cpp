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

#include <lulznet/config.h>
#include <lulznet/log.h>
#include <lulznet/networking.h>
#include <lulznet/peer.h>
#include <lulznet/tap.h>
#include <lulznet/shell.h>
#include <lulznet/xfunc.h>

void Shell::peer_preconnect (Cmd * cmd)
{
  int address;
  unsigned short port;

  if (cmd->argc < 1)
    std::cout << "Usage: connect address [port]" << std::endl;
  else if (cmd->argc == 1)
    {
      address = Network::lookup_address (cmd->argv[0]);
      if (address == 0)
        return;

      Network::Client::peer_connect (address, 7890);
    }
  else
    {
      address = xinet_pton ((char *) cmd->argv[0].c_str ());
      port = atoi ((char *) cmd->argv[1].c_str ());

      Network::Client::peer_connect (address, port);
    }

}

void Shell::peer_list ()
{
  int i;
  int j;
  int tmp;
  char address[ADDRESS_LEN + 1];
  char network[ADDRESS_LEN + 1];
  char netmask[ADDRESS_LEN + 1];
  Peers::Peer * peer;

  for (i = 0; i < Peers::count; i++)
    {
      peer = Peers::db[i];

      tmp = peer->address ();
      inet_ntop (AF_INET, &tmp, address, ADDRESS_LEN);

      printf ("%s:\n\t[*] filedescriptor: %d\n\t[*] address: %s",
              peer->user ().c_str (), peer->fd (), address);
      printf ("\n\t[*] available networks: %d\n", 1);

      for (j = 0; j < peer->nl ().count; j++)
        {

          inet_ntop (AF_INET, &peer->nl ().network[j], network, ADDRESS_LEN);
          inet_ntop (AF_INET, &peer->nl ().netmask[j], netmask, ADDRESS_LEN);

          printf ("\t\t[*] network:%s netmask:%s\n", network, netmask);
        }
      printf ("\n");
    }
}

void Shell::peer_kill (Cmd * cmd)
{
  int i;

  if (cmd->argc != 2)
    std::cout << "Usage: peer kill peer_name" << std::endl;
  else
    {
	 for ( i = 0; i < Peers::count; i++)
	      if(!Peers::db[i]->user().compare(cmd->argv[1])){
		   if(Peers::db[i]->isActive()){
			Peers::db[i]->disassociate();
			Peers::db[i] = NULL;
			Peers::rebuild_db();
		   }
		   else 
			std::cout << "Peer is not active" << std::endl;
		   
		   return;
		   }
	 std::cout << "Invalid user specified" << std::endl;
    }
}

void Shell::tap_list ()
{
  int i;
  int n_address;
  int n_netmask;
  char p_address[ADDRESS_LEN + 1];
  char p_netmask[ADDRESS_LEN + 1];
  Taps::Tap * tap;

  for (i = 0; i < Taps::count; i++)
    {
      tap = Taps::db[i];
      n_address = tap->address();
      n_netmask = tap->netmask();

      std::cout << tap->device () << ":\n\t[*] filedecriptor: " << tap->fd () << std::endl;

      inet_ntop (AF_INET, &n_address, p_address, ADDRESS_LEN);
      inet_ntop (AF_INET, &n_netmask, p_netmask, ADDRESS_LEN);

      std::cout << "\t[*] address: " << p_address << " netmask: " << p_netmask << std::endl;
    }
}


Shell::Cmd *
Shell::preparse_command (std::string line)
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

void Shell::parse_command (Shell::Cmd * cmd)
{

  /* peer command */
  if (!cmd->command.compare ("peer"))
    {
      if (!cmd->argc)
        std::cout << "Usage: peer [ list | kill ]" << std::endl;
      else if (!cmd->argv[0].compare ("list"))
        peer_list ();
      else if (!cmd->argv[0].compare ("kill"))
        peer_kill (cmd);
      else
        Log::error ("Unknow arg");
    }

  /* tap command */
  else if (!cmd->command.compare ("tap"))
    {
      if (!cmd->argc)
        std::cout << "Usage: tap [ list | add | del ]" << std::endl;
      else if (!cmd->argv[0].compare ("list"))
        tap_list ();
      else if (!cmd->argv[0].compare ("add"))
        {
          /* TODO: add all stuff */
        }
      else if (!cmd->argv[0].compare ("del"))
        {
          /* TODO: add all stuff */
        }
      else
        Log::error ("Unknow arg");
    }

  /* connect peer command */
  else if (!cmd->command.compare ("connect"))
    {
      if (!cmd->argc)
        std::cout << "Usage: connect [address] [port]" << std::endl;
      else
        peer_preconnect (cmd);
    }

  /* useless command */
  else if (!cmd->command.compare ("whoami"))
    printf ("%s\n", options.username ().c_str ());

  /* quit command */
  else if (!cmd->command.compare ("quit"))
    exit_lulznet ();

  /* invalid command */
  else
    std::cout << cmd->command.c_str () << ": command not found." << std::endl;
}

void Shell::start ()
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
              if ((cmd = preparse_command (line)))
                {
                  parse_command (cmd);
                  add_history (line.c_str ());
                }
              delete cmd;
            }
        }
    }
}
