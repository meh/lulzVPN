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
#include <lulznet/types.h>

#include <lulznet/config.h>
#include <lulznet/log.h>
#include <lulznet/networking.h>
#include <lulznet/peer.h>
#include <lulznet/shell.h>
#include <lulznet/tap.h>
#include <lulznet/xfunc.h>


int
main (int argc, char *argv[])
{

  int address;
  pthread_t server_t;		/* Listening thread */

  set_default_options ();
  parse_config_file ((char *) CONFIG_FILE);
  parse_args (argc, argv);
  check_empty_config_entry ();

  if (getuid () && (opt.flags & LISTEN_MODE))
    fatal ("You must be super user");

  printf ("~~ Starting lulzNet =^_^= ~~\nlulz peer2peer VPN %s", VERSION);
  fflush (stdout);

  lulznet_init ();

  if (!new_tap (opt.tap_address, opt.tap_netmask))
    fatal ("Cannot create new tap");

  if (opt.flags & LISTEN_MODE)
    pthread_create (&server_t, NULL, server_loop, NULL);
  else
    debug1 ("Not listening");

  if (opt.connecting_address != NULL)
    {
      address = lookup_address (opt.connecting_address);
      peer_connect (address, opt.connecting_port);
    }

  pthread_create (&select_t, NULL, select_loop, NULL);

  if (opt.flags & INTERACTIVE_MODE)
    start_shell ();
  else
    debug1 ("Non interactive mode");

  pthread_join (select_t, NULL);
  pthread_join (server_t, NULL);

  return 0;
}

void
lulznet_init ()
{
  int sysctl_name[3];
  int sysctl_newval[1];
  int sysctl_newlen;

  memset (peer_db, '\x00', MAX_PEERS * sizeof (peer_handler_t));
  peer_count = 0;
  max_peer_fd = 0;

  memset (tap_db, '\x00', MAX_TAPS * sizeof (tap_handler_t));
  tap_count = 0;
  max_tap_fd = 0;
  FD_ZERO (&master);

  memset (&select_t, '\x00', sizeof (pthread_t));
  pthread_mutex_init (&select_mutex, NULL);

  SSL_load_error_strings ();
  SSLeay_add_ssl_algorithms ();
  OpenSSL_add_all_digests ();

  ssl_server_init ();
  ssl_client_init ();

  sysctl_name[0] = CTL_NET;
  sysctl_name[1] = NET_IPV4;
  sysctl_name[2] = NET_IPV4_FORWARD;
  sysctl_newlen = sizeof (sysctl_name);
  sysctl_newval[0] = 1;
  sysctl (sysctl_name, 3, NULL, 0, sysctl_newval, sysctl_newlen);

  signal (SIGINT, sigint_handler);
}

void
help ()
{
  printf ("lulznet :: lulz p2p vpn\n");
  printf ("version %s\n", VERSION);

  printf ("usage: lulznet [options]\n");
  printf ("OPTIONS:\n");
  printf ("-b\t specify server binding address\n");
  printf ("-c\tspecify a server to connect\n");
  printf ("-h\tdisplay this help\n");
  printf ("-i\tstart interactive shell\n");
  printf ("-l\tspecify user\n");
  printf ("-n\tdisable server listening\n");
  printf ("-p\tspecify connecting port");
  printf ("-P\tspecify server listening port");
  printf ("-t\tSpecify tap address\n");
  printf ("-v\tIncrease debug level\n");

  exit (0);
}

void
exit_lulznet ()
{

  int i;
  peer_handler_t *peer;

  info ("Closing lulznet");

  for (i = 0; i < peer_count; i++)
    {
      peer = peer_db + i;
      peer_disconnect (peer->fd);
    }

  printf ("\n");

  exit (0);
}

void
sigint_handler (int signal __attribute__ ((unused)))
{
  exit_lulznet ();
}
