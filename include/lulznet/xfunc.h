/*
 * "xfunc.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

/* safe function, with error handling */

void *xmalloc (size_t size);
void *xrealloc (void *ptr, size_t size);
void xfree (void *);

int xSSL_read (SSL * ssl, void *buf, int max_len, const char *item);
int xSSL_write (SSL * ssl, void *buf, int max_len, const char *item);

int xinet_pton (char *address);
