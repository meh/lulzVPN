/*
 * "config.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

Config::Config ()
{
  _flags = 0;
  _connecting_port = PORT;
  _binding_port = PORT;
#ifdef DEBUG
  _debug_level = 0;
#endif
}

int Config::flags ()
{
  return _flags;
}

short Config::connecting_port ()
{
  return _connecting_port;
}

short Config::binding_port ()
{
  return _binding_port;
}

std::string Config::connecting_address ()
{
  return _connecting_address;
}

std::string Config::binding_address ()
{
  return _binding_address;
}

std::string Config::tap_address ()
{
  return _tap_address;
}

std::string Config::tap_netmask ()
{
  return _tap_netmask;
}

std::string Config::username ()
{
  return _username;
}

std::string Config::password ()
{
  return _password;
}

void Config::password (std::string password)
{
  _password = password;
}

#ifdef DEBUG
int Config::debug_level ()
{
  return _debug_level;
}
#endif

void Config::ParseArgs (int argc, char **argv)
{
  int c;
  char optopt = '\x00';
  opterr = 0;

  while ((c = getopt (argc, argv, "ac:dhil:n:p:P:t:v")) != -1)
    switch (c)
      {
      case 'c':
        if (!*optarg)
          Log::Fatal ("You must specify an address");
        else
          _connecting_address = optarg;
        break;
      case 'd':
        _flags ^= LISTEN_MODE;
        break;
      case 'h':
        help ();
        break;
      case 'i':
        _flags |= INTERPEER_ACTIVE_MODE;
        break;
      case 'l':
        _username = optarg;
        break;
      case 'n':
        if (!*optarg)
          Log::Fatal ("You must specify a netmask");
        else
          _tap_netmask = optarg;
        break;
      case 'p':
        if (!*optarg)
          Log::Fatal ("You must specify a port");
        else
          _connecting_port = (short) atoi (optarg);
        break;
      case 'P':
        if (!*optarg)
          Log::Fatal ("You must specify a port");
        else
          _binding_port = (short) atoi (optarg);
        break;
      case 't':
        if (!*optarg)
          Log::Fatal ("You must specify an address");
        else
          _tap_address = optarg;
        break;
#ifdef DEBUG
      case 'v':
        _debug_level++;
        break;
#endif
      case '?':
        if (optopt == 'p' || optopt == 'c')
          Log::Fatal ("Option -%c requires an argument.\n", optopt);
        else if (isprint (optopt))
          Log::Fatal ("Unknown option `-%c'.\n", optopt);
        else
          Log::Fatal ("Unknown option character `\\x%x'.\n", optopt);
      }
}

void Config::ParseConfigFile (char *filename)
{
  FILE *fp;
  char tmp[33];
  char c;

  fp = fopen (filename, "r");

  if (fp == NULL)
    Log::Fatal ("Cannot open config file %s", filename);
  else
    {
      while (fscanf (fp, "%32s", tmp) != -1)
        {
          if (!strcmp (tmp, "user"))
            {
              fscanf (fp, "%32s", tmp);
              _username = tmp;
            }
          if (!strcmp (tmp, "password"))
            {
              fscanf (fp, "%32s", tmp);
              _password = tmp;
            }
          else if (!strcmp (tmp, "tap_addr"))
            {
              fscanf (fp, "%32s", tmp);
              _tap_address = tmp;
            }
          else if (!strcmp (tmp, "tap_netm"))
            {
              fscanf (fp, "%32s", tmp);
              _tap_netmask = tmp;
            }
          else if (!strcmp (tmp, "interactive"))
            {
              fscanf (fp, "%32s", tmp);
              if (!strcmp (tmp, "yes"))
                _flags |= INTERPEER_ACTIVE_MODE;
              else if (!strcmp (tmp, "no"))
                {
                  if (_flags & INTERPEER_ACTIVE_MODE)
                    _flags ^= INTERPEER_ACTIVE_MODE;
                }
              else
                Log::Error ("Invalid option");
            }
          else if (!strcmp (tmp, "listening"))
            {
              fscanf (fp, "%32s", tmp);
              if (!strcmp (tmp, "yes"))
                _flags |= '\x01';
              else if (!strcmp (tmp, "no"))
                {
                  if (_flags & LISTEN_MODE)
                    _flags ^= LISTEN_MODE;
                }
              else
                Log::Error ("Invalid option");
            }
#ifdef DEBUG
          else if (!strcmp (tmp, "debug"))
            {
              fscanf (fp, "%32s", tmp);
              _debug_level = atoi (tmp);
            }
#endif
          else if (!tmp[0] == '#')
            Log::Error ("Invalid option in configfile");

          do
            fscanf (fp, "%c", &c);
          while (c != '\n');
        }
    }
}

void Config::ChecEmptyConfigEntry ()
{
  if (_tap_address.empty ())
    Log::Fatal ("You must specify a tap address");

  if (_username.empty ())
    Log::Fatal ("You must specify an username");
}
