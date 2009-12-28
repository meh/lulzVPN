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

namespace Shell
{

typedef struct
{
  std::string command;
  std::string argv[4];
  int argc;
} Cmd;

void PeerPreconnect (Cmd * cmd);
void PeerList ();
void PeerKill (Cmd * cmd);

void TapList ();

void CredList ();

void Help();

/* Parsing command stuff */
Cmd *PreparseCommand (std::string line);
void ParseCommand (Cmd * cmd);

void Start ();
}
#endif
