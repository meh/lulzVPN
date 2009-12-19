/*
   * "config.h" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
   *
   * lulzNet is free software; you can redistribute it and/or modify
   * it under the terms of the GNU General Public License as published by
   * the Free Software Foundation; either version 3 of the License, or
   * (at your option) any later version.
   *
   * lulzNet is distributed in the hope that it will be useful,
   * but WITHOUT ANY WARRANTY; without even the implied warranty of
   * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   * GNU General Public License for more details.
   *
   * You should have received a copy of the GNU General Public License
   * along with this program; if not, write to the Free Software
   * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
   * MA 02110-1301, USA.
   */
#include <iostream>
#include <string>
#include <vector>

#ifndef _LNET_CONFIG_H
#define _LNET_CONFIG_H

#define CONFIG_FILE "/etc/lulznet/config.xml"

#define LISTENING_MODE 0x01
#define AUTH_SERVICE 0x02
#define INTERACTIVE_MODE 0x04

struct TapDeviceT
{
  std::string NetworkName;
  std::string Address;
  std::string Netmask;
};

struct UserCredentialT
{
  std::string Name;
  std::string Hash;
};

class Config
{

private:
  int _Flags;

  std::string _ConnectingAddress;
  short _ConnectingPort;
  std::string _BindingAddress;
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
  std::string ConnectingAddress ();
  std::string BindingAddress ();
  short ConnectingPort ();
  short BindingPort ();
  std::string Username ();
  std::string Password ();
  void Password (std::string password);
#ifdef DEBUG
  int DebugLevel ();
#endif

  int TapDevicesCount();
  TapDeviceT TapDevice(int i);

  int UserCredentialsCount();
  UserCredentialT UserCredentials(int i);

public:
  /* parse console args */
  void ParseArgs (int argc, char **argv);
  /* parse config file */
  void ParseConfigFile (char *filename);

  /* Xml Parser */
  void ParseConfig (xmlDocPtr doc, xmlNodePtr curNode);
  void ParseUserNet (xmlDocPtr doc, xmlNodePtr curNode);
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
