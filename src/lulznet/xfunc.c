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

#include "headers/lulznet.h"

void *
xmalloc (size_t size)
{
  void *ptr;

  if (size == 0)
    fatal ("xmalloc: zero size");
  ptr = malloc (size);
  if (ptr == NULL)
    fatal ("xmalloc: out of memory (allocating %lu bytes)", (u_long) size);
  return ptr;
}

void *
xrealloc (void *ptr, size_t size)
{
  void *new_ptr;

  if (size == 0)
    fatal ("xrealloc: zero size");
  if (ptr == NULL)
    new_ptr = malloc (size);
  else
    new_ptr = realloc (ptr, size);
  if (new_ptr == NULL)
    fatal ("xrealloc: out of memory (size %lu bytes)", (u_long) size);
  return new_ptr;
}

void
xfree (void *ptr)
{
  if (ptr == NULL)
    fatal ("xfree: NULL pointer given as argument");
  free (ptr);
}

int
xSSL_read (SSL * ssl, void *buf, int max_len, char *item)
{

  char ssl_err_msg[64];
  int rd_len;

  if (!(rd_len = SSL_read (ssl, buf, max_len)))
    {
      sprintf (ssl_err_msg, "cannot recv %s", item);
      error (ssl_err_msg);
      rd_len = 0;
    }
  return rd_len;
}

int
xSSL_write (SSL * ssl, void *buf, int max_len, char *item)
{

  char ssl_err_msg[64];
  int wr_len;

  if (!(wr_len = SSL_write (ssl, buf, max_len)))
    {
      sprintf (ssl_err_msg, "cannot send %s", item);
      error (ssl_err_msg);
      wr_len = 0;
    }
  return wr_len;
}

int
xinet_pton (char *address)
{
  int int_addr;

  if (inet_pton (AF_INET, address, &int_addr) < 0)
    {
      error ("Invalid address format");
      return 0;
    }
  else
    return int_addr;

}
