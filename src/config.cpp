/*
 * "config.c" (C) blawl ( j[dot]segf4ult[at]gmail[dot]com )
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

#include <lulznet/config.h>
#include <lulznet/log.h>
#include <lulznet/networking.h>

Config::Config()
{
  _Flags = 0;
  _ConnectingPort = port;
  _BindingPort = port;

#ifdef DEBUG
  _DebugLevel = 0;
#endif
}

int
Config::Flags ()
{
  return _Flags;
}

short
Config::ConnectingPort ()
{
  return _ConnectingPort;
}

short
Config::BindingPort ()
{
  return _BindingPort;
}

const std::string&
Config::ConnectingAddress ()
{
  return _ConnectingAddress;
}

const std::string&
Config::BindingAddress ()
{
  return _BindingAddress;
}

const std::string&
Config::Username ()
{
  return _Username;
}

const std::string&
Config::Password ()
{
  return _Password;
}

void
Config::Password (std::string password)
{
  _Password = password;
}

#ifdef DEBUG
int
Config::DebugLevel ()
{
  return _DebugLevel;
}
#endif

const std::vector<TapDeviceT>&
Config::TapDevices ()
{
  return _TapDevices;
}

const std::vector<UserCredentialT>&
Config::UserCredentials ()
{
  return _UserCredentials;
}

void
Config::ParseArgs (int argc, char **argv)
{
  int c;
  char optopt = '\x00';
  opterr = 0;

  while ((c = getopt(argc, argv, "ac:dhil:n:p:P:t:v")) != -1)
    switch (c) {
    case 'c':
      if (!*optarg)
        Log::Fatal("You must specify an address");
      else
        _ConnectingAddress = optarg;
      break;
    case 'd':
      _Flags ^= listeningMode;
      break;
    case 'h':
      help();
      break;
    case 'i':
      _Flags |= interactiveMode;
      break;
    case 'l':
      _Username = optarg;
      break;
    case 'p':
      if (!*optarg)
        Log::Fatal("You must specify a port");
      else
        _ConnectingPort = static_cast<short>(atoi(optarg));
      break;
    case 'P':
      if (!*optarg)
        Log::Fatal("You must specify a port");
      else
        _BindingPort = static_cast<short>(atoi(optarg));
      break;
#ifdef DEBUG
    case 'v':
      _DebugLevel++;
      break;
#endif
    case '?':
      if (optopt == 'p' || optopt == 'c')
        Log::Fatal("Option -%c requires an argument.\n", optopt);
      else if (isprint(optopt))
        Log::Fatal("Unknown option `-%c'.\n", optopt);
      else
        Log::Fatal("Unknown option character `\\x%x'.\n", optopt);
    }
}

void
Config::ParseConfigFile (std::string filename)
{
  xmlDocPtr doc;
  xmlNodePtr curNode;

  doc = xmlParseFile(filename.c_str());

  if (doc == NULL) {
    Log::Error("Document not parsed successfully.");
    return;
  }

  curNode = xmlDocGetRootElement(doc);
  if (curNode == NULL) {
    Log::Fatal("Empty config file");
    xmlFreeDoc(doc);
    return;
  }

  if (xmlStrcmp(curNode->name, (const xmlChar *) "lulzNetConfig")) {
    Log::Fatal("This is not a valid lulznet config file.\nRoot node != lulzNetConfig");
    xmlFreeDoc(doc);
    return;
  }

  curNode = curNode->xmlChildrenNode;
  while (curNode != NULL) {
    if ((!xmlStrcmp(curNode->name, reinterpret_cast<const xmlChar *>("config"))))
      ParseConfig(doc, curNode);
    else if ((!xmlStrcmp(curNode->name, reinterpret_cast<const xmlChar *>("users"))))
      ParseUsers(doc, curNode);
    else if ((!xmlStrcmp(curNode->name, reinterpret_cast<const xmlChar *>("taps"))))
      ParseTaps(doc, curNode);

    curNode = curNode->next;
  }

  xmlFreeDoc(doc);
  return;

}

void
Config::ChecEmptyConfigEntry ()
{
  if (!_TapDevices.size())
    Log::Fatal("You must specify a tap address");

  if (_Username.empty())
    Log::Fatal("You must specify an username");
}

void
Config::ParseConfig (xmlDocPtr doc, xmlNodePtr curNode)
{
  xmlChar *key;
  curNode = xmlFirstElementChild(curNode);

  while (curNode != NULL) {
    if ((!xmlStrcmp(curNode->name, reinterpret_cast<const xmlChar *>("username")))) {
      key = xmlNodeListGetString(doc, curNode->xmlChildrenNode, 1);
      _Username = reinterpret_cast<char *>(key);
      xmlFree(key);
    }
    else if ((!xmlStrcmp(curNode->name, reinterpret_cast<const xmlChar *>("password")))) {
      key = xmlNodeListGetString(doc, curNode->xmlChildrenNode, 1);
      _Password = reinterpret_cast<char *>(key);
      xmlFree(key);
    }
    else if ((!xmlStrcmp(curNode->name, reinterpret_cast<const xmlChar *>("listening")))) {
      key = xmlNodeListGetString(doc, curNode->xmlChildrenNode, 1);
      if (!strcmp(reinterpret_cast<char *>(key), "yes"))
        _Flags |= listeningMode;
      else if (!strcmp(reinterpret_cast<char *>(key), "no")) {
        if (_Flags & listeningMode)
          _Flags ^= listeningMode;
      }
      xmlFree(key);
    }
    else if ((!xmlStrcmp(curNode->name, reinterpret_cast<const xmlChar *>("interactive")))) {
      key = xmlNodeListGetString(doc, curNode->xmlChildrenNode, 1);
      if (!strcmp(reinterpret_cast<char *>(key), "yes"))
        _Flags |= interactiveMode;
      else if (!strcmp(reinterpret_cast<char *>(key), "no")) {
        if (_Flags & interactiveMode)
          _Flags ^= interactiveMode;
      }
      xmlFree(key);
    }
#ifdef DEBUG
    else if ((!xmlStrcmp(curNode->name, reinterpret_cast<const xmlChar *>("debug")))) {
      key = xmlNodeListGetString(doc, curNode->xmlChildrenNode, 1);
      _DebugLevel = atoi(reinterpret_cast<char *>(key));
      xmlFree(key);
    }
#endif
    else
      Log::Error("Invalid option in lulznet config (%s)", curNode->name);

    curNode = xmlNextElementSibling(curNode);
  }
  return;
}

std::vector < std::string >
Config::ParseUserNet (xmlDocPtr doc, xmlNodePtr curNode)
{
  xmlChar *key;
  std::vector < std::string > AllowedNetworks;
  curNode = xmlFirstElementChild(curNode);

  while (curNode != NULL) {
    if ((!xmlStrcmp(curNode->name, reinterpret_cast<const xmlChar *>("name")))) {
      key = xmlNodeListGetString(doc, curNode->xmlChildrenNode, 1);
      AllowedNetworks.push_back(reinterpret_cast<char *>(key));
      xmlFree(key);
    }
    else
      Log::Error("Invalid option in allowed net config");

    curNode = xmlNextElementSibling(curNode);
  }
  return AllowedNetworks;
}

void
Config::ParseUser (xmlDocPtr doc, xmlNodePtr curNode)
{
  xmlChar *key;
  UserCredentialT UserCredTmp;

  curNode = xmlFirstElementChild(curNode);

  while (curNode != NULL) {
    if ((!xmlStrcmp(curNode->name, reinterpret_cast<const xmlChar *>("name")))) {
      key = xmlNodeListGetString(doc, curNode->xmlChildrenNode, 1);
      UserCredTmp.Name = (reinterpret_cast<char *>(key));
      xmlFree(key);
    }
    else if ((!xmlStrcmp(curNode->name, reinterpret_cast<const xmlChar *>("hash")))) {
      key = xmlNodeListGetString(doc, curNode->xmlChildrenNode, 1);
      UserCredTmp.Hash = (reinterpret_cast<char *>(key));
      xmlFree(key);
    }
    else if ((!xmlStrcmp(curNode->name, reinterpret_cast<const xmlChar *>("allowedTap"))))
      UserCredTmp.AllowedNetworks = ParseUserNet(doc, curNode);
    else
      Log::Error("Invalid option in user config");

    curNode = xmlNextElementSibling(curNode);
  }

  if (!(UserCredTmp.Name.empty() || UserCredTmp.Hash.empty()))
    _UserCredentials.push_back(UserCredTmp);

  return;
}

void
Config::ParseUsers (xmlDocPtr doc, xmlNodePtr curNode)
{
  curNode = xmlFirstElementChild(curNode);

  while (curNode != NULL) {
    if ((!xmlStrcmp(curNode->name, reinterpret_cast<const xmlChar *>("user"))))
      ParseUser(doc, curNode);
    else
      Log::Error("Invalid option in users config");

    curNode = xmlNextElementSibling(curNode);
  }

  return;
}

void
Config::ParseTap (xmlDocPtr doc, xmlNodePtr curNode)
{
  xmlChar *key;
  curNode = xmlFirstElementChild(curNode);

  TapDeviceT TapDeviceTmp;

  while (curNode != NULL) {
    if ((!xmlStrcmp(curNode->name, reinterpret_cast<const xmlChar *>("name")))) {
      key = xmlNodeListGetString(doc, curNode->xmlChildrenNode, 2);
      TapDeviceTmp.networkName = (reinterpret_cast<char *>(key));
      xmlFree(key);
    }
    else if ((!xmlStrcmp(curNode->name, reinterpret_cast<const xmlChar *>("address")))) {
      key = xmlNodeListGetString(doc, curNode->xmlChildrenNode, 1);
      TapDeviceTmp.Address = (reinterpret_cast<char *>(key));
      xmlFree(key);
    }
    else if ((!xmlStrcmp(curNode->name, reinterpret_cast<const xmlChar *>("netmask")))) {
      key = xmlNodeListGetString(doc, curNode->xmlChildrenNode, 1);
      TapDeviceTmp.Netmask = (reinterpret_cast<char *>(key));
      xmlFree(key);
    }
    else
      Log::Error("Invalid option in tap config");

    curNode = xmlNextElementSibling(curNode);
  }

  if (!(TapDeviceTmp.networkName.empty() || TapDeviceTmp.Address.empty()
        || TapDeviceTmp.Netmask.empty()))
    _TapDevices.push_back(TapDeviceTmp);

  return;

}

void
Config::ParseTaps (xmlDocPtr doc, xmlNodePtr curNode)
{
  curNode = xmlFirstElementChild(curNode);

  while (curNode != NULL) {
    if ((!xmlStrcmp(curNode->name, reinterpret_cast<const xmlChar *>("tap"))))
      ParseTap(doc, curNode);
    else
      Log::Error("Invalid option in taps config");

    curNode = xmlNextElementSibling(curNode);
  }
  return;
}
