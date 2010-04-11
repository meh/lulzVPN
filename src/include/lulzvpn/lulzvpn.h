/*
 * "lulzvpn.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

//#pragma warning (disable:981)

#include <iostream>
#include <string>
#include <vector>

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <netdb.h>
#include <ctype.h>
#include <signal.h>
#include <pthread.h>
#include <termio.h>

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
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#include <readline/readline.h>
#include <readline/history.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "_config.h"

#define DEBUG

#ifndef _LVPN_LULZVPN_H
#define _LVPN_LULZVPN_H

const bool FAIL = false;
const bool DONE = true;

typedef unsigned char uChar;
typedef unsigned short uShort;
typedef unsigned int uInt;

#define MAX(A,B) ((A)>(B) ? (A) : (B))

/* Show a little help */
void help ();

/* lulzvpn initialization */
void LulzVPNInit ();

/* Close fd, send disconnect packet to all peer and all that stuff */
void LulzVPNExit ();

/* Don't close lulzvpn with signal */
void sigHandler (__attribute__ ((unused)) int signal);

#endif
