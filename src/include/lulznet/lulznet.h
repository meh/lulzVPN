/*
 * "lulznet.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <netdb.h>
#include <ctype.h>
#include <signal.h>
#include <pthread.h>
#include <termio.h>

#include <iostream>
#include <string>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/sysctl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "_config.h"

#ifndef _LNET_LULZNET_H
#define _LNET_LULZNET_H

#define FALSE	0
#define TRUE	1

#define FAIL	0
#define DONE	1

#define u_char	unsigned char
#define u_short	unsigned short
#define u_int 	unsigned int

#define MAX_ACCEPTED_PEERS_CONNECTIONS	4
#define	MAX_CONNECTIONS_TO_PEER		4
#define MAX_PEERS 			8

#define MAX_TAPS	8
#define ADDRESS_LEN	16

#define VERSION "0.0.1 [+ssl]"
#define MAX(A,B) ((A)>(B) ? (A):(B))

/* Show a little help */
void help ();

/* lulznet initialization */
void lulznet_init ();

/* Close fd, send disconnect packet to all peer and all that stuff */
void exit_lulznet ();

/* Don't close lulznet with signal */
void sigint_handler (int signal __attribute__ ((unused)));

#endif
