typedef struct
{

#define LISTEN_MODE		'\x01'
#define INTERACTIVE_MODE	'\x02'

  int flags;
  short connecting_port;
  short binding_port;
  char *connecting_address;
  char *binding_address;
  char *tap_address;
  char *tap_netmask;
  char *username;
} option_t;

typedef struct
{
  char *user[MAX_PEERS];
  int address[MAX_PEERS];

  int count;
} user_list_t;

typedef struct
{

  /* XXX: fix remote bof */
  char *device[MAX_TAPS];
  int address[MAX_TAPS];
  int network[MAX_TAPS];
  int netmask[MAX_TAPS];

  int count;
} network_list_t;

/* This struct holds remote peers informations */
typedef struct
{
  /* related file descriptor */
  int fd;
  SSL *ssl;

  /* Various flags (active etc) */
  char flags;

  /* remote peer username and address */
  char *user;
  int address;

  /* peer's lulz device info */
  network_list_t *nl;

} peer_handler_t;

typedef struct
{
  int fd;
  char flags;
  char *device;
  int address;
  int netmask;
  int network;

  char *allowed_users[MAX_PEERS];
  int allowed_users_count;

} tap_handler_t;


typedef struct
{
  char flags;
  char *peer_username;

  user_list_t *user_list;
  network_list_t *network_list;
} handshake_opt_t;

typedef struct
{
  char command[33];
  char argv[4][128];
  int argc;
} sh_cmd;
