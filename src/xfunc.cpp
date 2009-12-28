/*
 * "xfunc.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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
#include <lulznet/log.h>
#include <lulznet/xfunc.h>

int
xSSL_read (SSL * ssl, void *buf, int max_len, const char *item)
{

  int rdLen;

  rdLen = SSL_read(ssl, buf, max_len);

  if (!rdLen)
    Log::Error("cannot recv %s", item);

  return rdLen;
}

int
xSSL_write (SSL * ssl, void *buf, int max_len, const char *item)
{

  int wr_len;

  wr_len = SSL_write(ssl, buf, max_len);

  if (!wr_len)
    Log::Error("cannot send %s", item);

  return wr_len;
}

int
xinet_pton (char *address)
{
  int int_addr;

  if (inet_pton(AF_INET, address, &int_addr) < 0) {
    Log::Error("Invalid address format");
    return 0;
  }
  else
    return int_addr;

}
