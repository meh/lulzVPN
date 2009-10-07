/*
 * "misc.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

int
/* Split into two function */
get_max_fd ()
{

  int i;
  int max = 0;

  for (i = 0; i < MAX_PEERS; i++)
    if (max < peer_db[i].fd)
      max = peer_db[i].fd;

  for (i = 0; i < MAX_TAPS; i++)
    if (max < tap_db[i].fd)
      max = tap_db[i].fd;
  return max;
}
