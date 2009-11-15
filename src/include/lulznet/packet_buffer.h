#include "protocol.h"

#ifndef LNET_PACKET_BUFFER
#define LNET_PACKET_BUFFER

namespace Network {

struct Packet {
  unsigned char buffer[5000];
  int length;
     }__attribute__ ((packed));
}
#endif
