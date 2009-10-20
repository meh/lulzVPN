/*
 * "shell.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

#ifndef _LNET_SHELL_H
#define _LNET_SHELL_H

typedef struct
{
  char command[33];
  char argv[4][128];
  int argc;
} sh_cmd;

void peer_preconnect (sh_cmd * cmd);
void peer_list ();
void peer_kill (sh_cmd * cmd);

void tap_list ();

/* Parsing command stuff */
sh_cmd *preparse_command (char *line);
void parse_command (sh_cmd * cmd);

void start_shell ();

#endif
