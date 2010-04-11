/*
 * "config.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
 *
 * lulzVPN is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * lulzVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */

#ifndef _LVPN_CONFIG_H
#define _LVPN_CONFIG_H

#include "lulzvpn.h"
#define CONFIG_FILE "/etc/lulzvpn/config.xml"

const char listeningMode = 0x01;
const char interactiveMode = 0x02;

struct TapDeviceT
{
  std::string networkName;
  std::string Address;
  std::string Netmask;
};

struct UserCredentialT
{
  std::string Name;
  std::string Hash;
  std::vector<std::string> AllowedNetworks;
};

class Config
{

private:
int _Flags;

int _MaxConnections;

std::string _ConnectingAddress;
std::string _BindingAddress;

short _ConnectingPort;
short _BindingPort;

std::string _Username;
std::string _Password;

#ifdef DEBUG
int _DebugLevel;
#endif

std::vector<TapDeviceT> _TapDevices;
std::vector<UserCredentialT> _UserCredentials;

public:
Config ();
int Flags ();
int MaxConnections();
const std::string& ConnectingAddress ();
const std::string& BindingAddress ();
short ConnectingPort ();
short BindingPort ();
const std::string& Username ();
const std::string& Password ();
void Password (std::string password);
#ifdef DEBUG
int DebugLevel ();
#endif

const std::vector<TapDeviceT>& TapDevices();
const std::vector<UserCredentialT>& UserCredentials();

public:
/* parse console args */
void ParseArgs (int argc, char **argv);
/* parse config file */
void ParseConfigFile (std::string filename);

/* Xml Parser */
void ParseConfig (xmlDocPtr doc, xmlNodePtr curNode);
std::vector<std::string> ParseUserNet (xmlDocPtr doc, xmlNodePtr curNode);
void ParseUser (xmlDocPtr doc, xmlNodePtr curNode);
void ParseUsers (xmlDocPtr doc, xmlNodePtr curNode);
void ParseTap (xmlDocPtr doc, xmlNodePtr curNode);
void ParseTaps (xmlDocPtr doc, xmlNodePtr curNode);

/* initialize struct opt */
void set_default_Options ();
/* check if something configuration is missing */
void ChecEmptyConfigEntry ();
};

extern Config Options;

#endif
