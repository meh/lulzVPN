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
#include <lulznet/types.h>

#include <lulznet/config.h>
#include <lulznet/log.h>
#include <lulznet/networking.h>
#include <lulznet/xfunc.h>

option_t opt;

void
parse_args (int argc, char **argv)
{
  int c;
  char optopt = '\x00';


  opterr = 0;

  while ((c = getopt (argc, argv, "ac:dhil:n:p:P:t:v")) != -1)
    switch (c)
      {
      case 'a':
	opt.flags |= AUTH_SERVICE;
      case 'c':
	if (!*optarg)
	  fatal ("You must specify an address");
	else
	  opt.connecting_address = optarg;
	break;
      case 'd':
	opt.flags ^= LISTEN_MODE;
	break;
      case 'h':
	help ();
	break;
      case 'i':
	opt.flags |= INTERACTIVE_MODE;
	break;
      case 'l':
	opt.username = optarg;
	break;
      case 'n':
	if (!*optarg)
	  fatal ("You must specify a netmask");
	else
	  opt.tap_netmask = optarg;
	break;
      case 'p':
	if (!*optarg)
	  fatal ("You must specify a port");
	else
	  opt.connecting_port = (short) atoi (optarg);
	break;
      case 'P':
	if (!*optarg)
	  fatal ("You must specify a port");
	else
	  opt.binding_port = (short) atoi (optarg);
	break;
      case 't':
	if (!*optarg)
	  fatal ("You must specify an address");
	else
	  opt.tap_address = optarg;
	break;
      case 'v':
	debug_level++;
	break;
      case '?':
	if (optopt == 'p' || optopt == 'c')
	  fatal ("Option -%c requires an argument.\n", optopt);
	else if (isprint (optopt))
	  fatal ("Unknown option `-%c'.\n", optopt);
	else
	  fatal ("Unknown option character `\\x%x'.\n", optopt);
      }
}

void
parse_config_file (char *filename)
{
  FILE *fp;
  char tmp[33];
  char c;

  fp = fopen (filename, "r");
  if (fp == NULL)
    error ("Cannot open config file %s", filename);
  else
    {

      while (fscanf (fp, "%32s", tmp) != -1)
	{
	  if (!strcmp (tmp, "user"))
	    {
	      fscanf (fp, "%32s", tmp);
	      opt.username = (char *) xmalloc ((strlen (tmp) + 1) * sizeof (char));
	      strcpy (opt.username, tmp);
	    }
	  else if (!strcmp (tmp, "tap_addr"))
	    {
	      fscanf (fp, "%32s", tmp);
	      opt.tap_address = (char *) xmalloc ((strlen (tmp) + 1) * sizeof (char));
	      strcpy (opt.tap_address, tmp);
	    }
	  else if (!strcmp (tmp, "tap_netm"))
	    {
	      fscanf (fp, "%32s", tmp);
	      opt.tap_netmask = (char *) xmalloc ((strlen (tmp) + 1) * sizeof (char));
	      strcpy (opt.tap_netmask, tmp);
	    }
	  else if (!strcmp (tmp, "interactive"))
	    {
	      fscanf (fp, "%32s", tmp);
	      if (!strcmp (tmp, "yes"))
		opt.flags |= INTERACTIVE_MODE;
	      else if (!strcmp (tmp, "no"))
		{
		  if (opt.flags & INTERACTIVE_MODE)
		    opt.flags ^= INTERACTIVE_MODE;
		}
	      else
		error ("Invalid option");
	    }
	  else if (!strcmp (tmp, "listening"))
	    {
	      fscanf (fp, "%32s", tmp);
	      if (!strcmp (tmp, "yes"))
		opt.flags |= '\x01';
	      else if (!strcmp (tmp, "no"))
		{
		  if (opt.flags & LISTEN_MODE)
		    opt.flags ^= LISTEN_MODE;
		}
	      else
		error ("Invalid option");
	    }
	  else if (!strcmp (tmp, "debug"))
	    {
	      fscanf (fp, "%32s", tmp);
	      debug_level = atoi (tmp);
	    }
	  else if (!tmp[0] == '#')
	    error ("Invalid option in configfile");

	  do
	    fscanf (fp, "%c", &c);
	  while (c != '\n');
	}
    }
}

void
set_default_options ()
{

  opt.flags = 0;
  opt.connecting_address = NULL;
  opt.binding_address = NULL;
  opt.tap_address = NULL;
  opt.tap_netmask = NULL;
  opt.connecting_port = PORT;
  opt.binding_port = PORT;
  opt.username = NULL;
  debug_level = 0;

}

void
check_empty_config_entry ()
{
  if (opt.tap_address == NULL)
    fatal ("You must specify a tap address");
  if (opt.username == NULL)
    fatal ("You must specify an username");
}
